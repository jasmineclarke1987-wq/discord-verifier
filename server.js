require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');
const client = require('./bot');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const dns = require('dns').promises;
const { parse } = require('tldts');
const disposableList = require('disposable-email-domains');

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('trust proxy', true);
app.use(express.static('public'));
app.use('/verify', rateLimit({ windowMs: 2 * 60 * 1000, max: 20 }));
app.use('/verify/confirm', rateLimit({ windowMs: 2 * 60 * 1000, max: 20 }));
app.use('/verify/resend', rateLimit({ windowMs: 5 * 60 * 1000, max: 5 }));

const {
  CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, TOKEN: BOT_TOKEN,
  MAIN_GUILD_ID, BACKUP_GUILD_ID,
  VERIFIED_ROLE_ID_MAIN, VERIFIED_ROLE_ID_BACKUP,
  LOG_CHANNEL_ID, BACKUP_INVITE_URL,
  ADMIN_USER, ADMIN_PASS,
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM,
  BRAND_NAME, BRAND_LOGO, BRAND_PRIMARY, BRAND_ACCENT, BRAND_BG
} = process.env;

// Toggle: set VPN_CHECK_ENABLED=false in env to allow VPNs
const VPN_CHECK_ENABLED = process.env.VPN_CHECK_ENABLED !== 'false';

const BRAND = {
  name: BRAND_NAME || 'ReturnPoint',
  logo: (BRAND_LOGO || '').trim(),
  primary: BRAND_PRIMARY || '#7c3aed',
  accent: BRAND_ACCENT || '#b794f4',
  bg: BRAND_BG || '#0b0b10',
};

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const VERIFIED_JSON = path.join(DATA_DIR, 'verified.json');
const PENDING_JSON = path.join(DATA_DIR, 'pending.json');

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(VERIFIED_JSON)) fs.writeFileSync(VERIFIED_JSON, '[]', 'utf8');
  if (!fs.existsSync(PENDING_JSON)) fs.writeFileSync(PENDING_JSON, '[]', 'utf8');
}
function readJson(file) { ensureStore(); return JSON.parse(fs.readFileSync(file, 'utf8')); }
function writeJson(file, data) { ensureStore(); fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8'); }
function saveVerified({ discordId, username, email }) {
  const arr = readJson(VERIFIED_JSON);
  arr.push({ discordId, username, email, verifiedAt: new Date().toISOString() });
  writeJson(VERIFIED_JSON, arr);
}

function requireAuth(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) return res.status(403).send('Admin auth not configured.');
  const hdr = req.headers.authorization || '';
  const b64 = hdr.startsWith('Basic ') ? hdr.slice(6) : '';
  const [u, p] = Buffer.from(b64 || ':', 'base64').toString().split(':');
  if (u === ADMIN_USER && p === ADMIN_PASS) return next();
  res.set('WWW-Authenticate', 'Basic realm="admin"');
  res.status(401).send('Auth required');
}

const DISPOSABLE_SET = new Set(disposableList.map(d => d.toLowerCase()));
const EXTRA_DISPOSABLE = (process.env.EXTRA_DISPOSABLE_DOMAINS || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
for (const d of EXTRA_DISPOSABLE) DISPOSABLE_SET.add(d);

const MX_BLOCK_PATTERNS = [
  /(^|\.)1secmail\.(org|com|net)$/i,
  /(^|\.)tempmail\.(email|io|dev|plus)$/i,
  /(^|\.)temp-mail\.(org|io)$/i,
  /(^|\.)guerrillamail\.com$/i,
  /(^|\.)yopmail\.com$/i,
  /(^|\.)mailinator\.com$/i,
  /(^|\.)trashmail\.(com|io)$/i,
  /(^|\.)getnada\.com$/i,
  /(^|\.)sharklasers\.com$/i,
  /(^|\.)moakt\.com$/i,
  /(^|\.)mohmal\.com$/i,
  /(^|\.)dropmail\.(me|me\.u?a?)$/i,
  /(^|\.)mintemail\.com$/i,
  /(^|\.)dispostable\.com$/i
];
const EXTRA_MX_BLOCK = (process.env.EXTRA_DISPOSABLE_MX || '')
  .split('|').map(s => s.trim()).filter(Boolean);
for (const pat of EXTRA_MX_BLOCK) { try { MX_BLOCK_PATTERNS.push(new RegExp(pat, 'i')); } catch {} }

function getDomains(email = '') {
  const at = email.lastIndexOf('@');
  if (at < 0) return {};
  const host = email.slice(at + 1).toLowerCase().trim();
  const info = parse(host);
  return { host, root: info.domain || host };
}

async function isDisposableOrInvalidEmail(email = '') {
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return true;
  const { host, root } = getDomains(email);
  if (!host || !root) return true;
  if (DISPOSABLE_SET.has(host) || DISPOSABLE_SET.has(root)) return true;
  let mx;
  try {
    mx = await dns.resolveMx(host);
    if (!mx || mx.length === 0) return true;
  } catch { return true; }
  const mxHosts = mx.map(r => (r && r.exchange ? String(r.exchange).toLowerCase() : ''));
  for (const h of mxHosts) if (MX_BLOCK_PATTERNS.some(rx => rx.test(h))) return true;
  return false;
}

const cookieSecure = process.env.NODE_ENV === 'production';
const cookieOpts = { httpOnly: true, sameSite: 'lax', secure: cookieSecure };

async function isVPNorProxy(ip) {
  try {
    if (!ip || ip === '::1' || ip === '127.0.0.1') return false;
    const resp = await axios.get(`http://ip-api.com/json/${ip}?fields=proxy,hosting,mobile,query`);
    const d = resp.data;
    return d.proxy === true || d.hosting === true;
  } catch (e) {
    console.error('[VPN CHECK] error:', e?.message || e);
    return false;
  }
}

async function exchangeCodeForToken({ code, clientId, clientSecret, redirectUri, fetchImpl }) {
  const fetchFn = fetchImpl || fetch;
  const form = () => new URLSearchParams({
    client_id: clientId, client_secret: clientSecret,
    grant_type: 'authorization_code', code, redirect_uri: redirectUri,
  });
  const maxAttempts = 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const resp = await fetchFn('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'rp-verifier/1.0 node-fetch' },
      body: form(),
    });
    if (resp.ok) return await resp.json();
    if (resp.status === 429 && attempt < maxAttempts) {
      const ra = Number(resp.headers.get('retry-after')) || 2;
      console.warn(`[CALLBACK] 429 token exchange. Retrying in ${ra}s (attempt ${attempt}/${maxAttempts})`);
      await new Promise(r => setTimeout(r, ra * 1000));
      continue;
    }
    const txt = await resp.text().catch(() => '');
    throw new Error(`token exchange failed: ${resp.status} ${txt}`);
  }
  throw new Error('token exchange failed after retries.');
}

function buildGuildIconURL(g) {
  if (!g || !g.id || !g.icon) return '';
  const ext = g.icon.startsWith('a_') ? 'gif' : 'png';
  return `https://cdn.discordapp.com/icons/${g.id}/${g.icon}.${ext}?size=256`;
}

async function resolveBrandLogo() {
  try {
    if (MAIN_GUILD_ID) {
      const guild = await client.guilds.fetch(MAIN_GUILD_ID);
      const icon = buildGuildIconURL(guild);
      if (icon) return icon;
    }
  } catch (e) { console.warn('[BRAND] Could not fetch guild icon:', e?.message || e); }
  if (BRAND.logo && !/(\?|&)ex=/.test(BRAND.logo)) return BRAND.logo;
  return '/logo.png';
}

async function getLogChannel() {
  const id = process.env.LOG_CHANNEL_ID;
  if (!id) throw new Error('LOG_CHANNEL_ID not set');
  try {
    const ch = await client.channels.fetch(id);
    if (!ch) throw new Error('Channel fetch returned null');
    return ch;
  } catch (e) {
    console.error('[LOG] fetch failed:', e?.message || e);
    throw e;
  }
}

async function sendVerificationLog({ discordId, email }) {
  try {
    const ch = await getLogChannel();
    const payload = {
      embeds: [{
        title: '✅ New verification',
        color: 0x57F287,
        fields: [
          { name: 'User', value: `<@${discordId}> (${discordId})`, inline: false },
          { name: 'Email', value: email || '—', inline: true }
        ],
        timestamp: new Date()
      }]
    };
    const msg = await ch.send(payload).catch(err => { console.error('[LOG] embed send failed:', err?.message || err); return null; });
    if (!msg) await ch.send(`✅ New verification: <@${discordId}> (${discordId}) | ${email || '—'}`).catch(err => console.error('[LOG] plaintext send failed:', err?.message || err));
  } catch (e) { console.error('[LOG] sendVerificationLog error:', e?.message || e); }
}

function makeTransport() {
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) {
    console.warn('[SMTP] Missing env (SMTP_HOST/PORT/USER/PASS/FROM). Emails will fail.');
  }
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT || 587),
    secure: false,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
}
const mailer = makeTransport();

function generateCode() {
  return (Math.floor(Math.random() * 1_000_000)).toString().padStart(6, '0');
}
async function sendOtpEmail(to, code) {
  const html = '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:16px">' +
    '<p>Here is your verification code:</p>' +
    `<p style="font-size:24px;font-weight:700;letter-spacing:3px">${code}</p>` +
    '<p>This code expires in <b>10 minutes</b>. If you didn’t request it, you can ignore this email.</p>' +
    '</div>';
  const text = 'Your verification code is: ' + code + '\nIt expires in 10 minutes.';
  await mailer.sendMail({ from: SMTP_FROM, to, subject: 'Your verification code', text, html });
}

function brandVars() {
  return `<style>:root{--brand-primary:${BRAND.primary};--brand-accent:${BRAND.accent};--brand-bg:${BRAND.bg};}</style>`;
}
function headerCard(title = 'Verify your account', subtitle = '', logoUrl = '') {
  const logoImg = logoUrl ? `<img class="logo" src="${logoUrl}" alt="${BRAND.name} logo">` : '';
  return `<div class="card">${logoImg}<h1 class="title">${title}</h1>${subtitle ? `<p class="subtitle">${subtitle}</p>` : ''}`;
}

app.get('/health', (_req, res) => res.status(200).send('ok'));

app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('oauth_state', state, { ...cookieOpts, maxAge: 10 * 60 * 1000 });
  const url = 'https://discord.com/api/oauth2/authorize'
    + `?client_id=${encodeURIComponent(CLIENT_ID)}`
    + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
    + `&response_type=code&scope=${encodeURIComponent('identify guilds.join')}`
    + `&state=${state}&prompt=consent`;
  res.redirect(url);
});

app.post('/verify', async (req, res) => {
  try {
    const email = (req.body && req.body.email) ? String(req.body.email).trim() : '';
    const discordId = req.cookies.discordId;
    const userAccessToken = req.cookies.userAccessToken;
    if (!email) return res.status(400).send('Please provide an email.');
    if (!discordId || !userAccessToken) return res.status(400).send('Session expired. Go to <a href="/login">/login</a>.');
    if (await isDisposableOrInvalidEmail(email)) return res.status(400).send('❌ Invalid email.');

    // IP policy
    let ip = req.ip;
    const fwd = req.headers['x-forwarded-for'];
    if (fwd && typeof fwd === 'string') ip = fwd.split(',')[0].trim();

    if (VPN_CHECK_ENABLED) {
      try {
        if (await isVPNorProxy(ip)) {
          return res.status(403).send('❌ Verification blocked: VPNs, proxies, and public Wi-Fi are not allowed. Please try again from home Wi-Fi or mobile data.');
        }
      } catch (e) {
        console.warn('[VPN CHECK] failed but continuing:', e?.message);
      }
    }

    const code = generateCode();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    const pending = readJson(PENDING_JSON).filter(p => p.discordId !== discordId);
    pending.push({ discordId, email, code, expiresAt, attempts: 0 });
    writeJson(PENDING_JSON, pending);

    try { await sendOtpEmail(email, code); }
    catch (e) { console.error('[SMTP] send failed:', e?.message || e); return res.status(500).send('Could not send email.'); }

    const logoUrl = await resolveBrandLogo();
    return res.send(`<html><head><link rel="stylesheet" href="/style.css">${brandVars()}</head><body><div class="wrap">${headerCard('Enter your code', 'We sent a <b>6-digit code</b> to <b>' + email + '</b>.', logoUrl)}<form action="/verify/confirm" method="POST" class="form"><input type="text" name="code" placeholder="6-digit code" required><button class="btn btn-primary" type="submit">Verify</button></form></div></body></html>`);
  } catch (e) { console.error('[VERIFY step1] error:', e); return res.status(500).send('Error sending code.'); }
});

// ----------------------------------------------------
// Render needs the app to listen on a port:
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
// ----------------------------------------------------
