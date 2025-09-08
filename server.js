require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');            // if Node < 18, installed as node-fetch@2
const client = require('./bot');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');

// NEW: stronger disposable-email detection deps (already installed in your project)
const dns = require('dns').promises;
const { parse } = require('tldts');
const disposableList = require('disposable-email-domains');

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('trust proxy', true);

// ✅ Serve static files (style.css in /public folder)
app.use(express.static('public'));

// ✅ Rate-limits
app.use('/verify', rateLimit({ windowMs: 2 * 60 * 1000, max: 20 }));          // email submit
app.use('/verify/confirm', rateLimit({ windowMs: 2 * 60 * 1000, max: 20 }));  // code submit (GET/POST)
app.use('/verify/resend', rateLimit({ windowMs: 5 * 60 * 1000, max: 5 }));    // resend

const {
  CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, TOKEN: BOT_TOKEN,
  MAIN_GUILD_ID, BACKUP_GUILD_ID,
  VERIFIED_ROLE_ID_MAIN, VERIFIED_ROLE_ID_BACKUP,
  LOG_CHANNEL_ID, BACKUP_INVITE_URL,
  ADMIN_USER, ADMIN_PASS,
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM,

  // 🔧 Optional branding variables (safe defaults below)
  BRAND_NAME,
  BRAND_LOGO,
  BRAND_PRIMARY,
  BRAND_ACCENT,
  BRAND_BG
} = process.env;

// 🔧 Branding defaults (can override via .env)
const BRAND = {
  name: BRAND_NAME || 'ReturnPoint',
  logo: BRAND_LOGO || 'https://cdn.discordapp.com/attachments/111111111111111111/111111111111111111/rp-logo.png',
  primary: BRAND_PRIMARY || '#7c3aed', // purple
  accent: BRAND_ACCENT || '#b794f4',
  bg: BRAND_BG || '#0b0b10',
};

// ✅ Data storage setup (supports Render disk via DATA_DIR)
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const VERIFIED_JSON = path.join(DATA_DIR, 'verified.json');
const PENDING_JSON = path.join(DATA_DIR, 'pending.json'); // NEW: pending OTPs

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

// ✅ Basic auth for admin CSV route
function requireAuth(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) return res.status(403).send('Admin auth not configured.');
  const hdr = req.headers.authorization || '';
  const b64 = hdr.startsWith('Basic ') ? hdr.slice(6) : '';
  const [u, p] = Buffer.from(b64 || ':', 'base64').toString().split(':');
  if (u === ADMIN_USER && p === ADMIN_PASS) return next();
  res.set('WWW-Authenticate', 'Basic realm="admin"');
  res.status(401).send('Auth required');
}

/* -------------------------------
   Strong disposable/invalid email
-------------------------------- */
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

/* -------------------------------
   Cookie options (secure in prod)
-------------------------------- */
const cookieSecure = process.env.NODE_ENV === 'production';
const cookieOpts = { httpOnly: true, sameSite: 'lax', secure: cookieSecure };

/* --------------------------------------
   VPN / proxy detector using ip-api.com
--------------------------------------- */
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

/* -----------------------------------------------------------------
   Helper: exchange auth code for token with retries/backoff
------------------------------------------------------------------ */
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

/* -----------------------------------
   LOGGING HELPERS
----------------------------------- */
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
  } catch (e) {
    console.error('[LOG] sendVerificationLog error:', e?.message || e);
  }
}

/* -----------------------------------
   EMAIL (SMTP) — send 6-digit OTP
----------------------------------- */
function makeTransport() {
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) {
    console.warn('[SMTP] Missing env (SMTP_HOST/PORT/USER/PASS/FROM). Emails will fail.');
  }
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT || 587),
    secure: false, // STARTTLS
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
}
const mailer = makeTransport();

function generateCode() {
  return (Math.floor(Math.random() * 1_000_000)).toString().padStart(6, '0');
}
async function sendOtpEmail(to, code) {
  const html = `
    <div style="font-family:Segoe UI,Arial,sans-serif;font-size:16px">
      <p>Here is your verification code:</p>
      <p style="font-size:24px;font-weight:700;letter-spacing:3px">${code}</p>
      <p>This code expires in <b>10 minutes</b>. If you didn’t request it, you can ignore this email.</p>
    </div>`;
  const text = `Your verification code is: ${code}\nIt expires in 10 minutes.`;
  await mailer.sendMail({ from: SMTP_FROM, to, subject: 'Your verification code', text, html });
}

/* -----------------------------------
   Small helpers for HTML (no nested backticks!)
----------------------------------- */
function brandVars() {
  return (
    '<style>' +
    ':root{' +
      `--brand-primary:${BRAND.primary};` +
      `--brand-accent:${BRAND.accent};` +
      `--brand-bg:${BRAND.bg};` +
    '}' +
    '</style>'
  );
}
function headerCard(title = 'Verify your account', subtitle = '') {
  const logoImg = BRAND.logo ? `<img class="logo" src="${BRAND.logo}" alt="${BRAND.name} logo">` : '';
  return (
    '<div class="card">' +
      logoImg +
      `<h1 class="title">${title}</h1>` +
      (subtitle ? `<p class="subtitle">${subtitle}</p>` : '')
  ); // NOTE: this opens <div class="card">; the page templates close it.
}

/* -----------------------------------
   /health → simple warm-up/monitor
----------------------------------- */
app.get('/health', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.status(200).send('ok');
});

/* -----------------------------------
   /login → send user to authorize (with state)
----------------------------------- */
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('oauth_state', state, { ...cookieOpts, maxAge: 10 * 60 * 1000 });

  const url = 'https://discord.com/api/oauth2/authorize'
    + `?client_id=${encodeURIComponent(CLIENT_ID)}`
    + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
    + `&response_type=code`
    + `&scope=${encodeURIComponent('identify guilds.join')}`
    + `&state=${state}`
    + `&prompt=consent`;
  res.redirect(url);
});

/* ----------------------------------------------------------
   /callback → exchange code, store cookies, show email form
---------------------------------------------------------- */
app.get('/callback', async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send('No code. Start again: <a href="/login">/login</a>');
    if (!req.query.state || req.query.state !== req.cookies.oauth_state) {
      return res.status(400).send('OAuth state mismatch. Please start again at <a href="/login">/login</a>.');
    }

    let access_token;
    try {
      const tok = await exchangeCodeForToken({ code, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, redirectUri: REDIRECT_URI, fetchImpl: fetch });
      access_token = tok.access_token;
    } catch (err) {
      const msg = String(err?.message || '');
      if (msg.includes('429')) return res.status(429).send('Rate-limited by Discord. Wait ~60s and try <a href="/login">/login</a>.');
      return res.status(400).send('OAuth failed. Try <a href="/login">/login</a>.');
    }
    if (!access_token) return res.status(400).send('No access_token. Try <a href="/login">/login</a>.');

    const meResp = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${access_token}`, 'User-Agent': 'rp-verifier/1.0 node-fetch' }});
    if (!meResp.ok) return res.status(400).send('Could not fetch user. Try <a href="/login">/login</a>.');
    const me = await meResp.json();

    res.cookie('discordId', me.id, cookieOpts);
    res.cookie('userAccessToken', access_token, cookieOpts);

    const subtitle = 'Welcome <b>' + me.username + '</b>! Enter your email to continue.';

    return res.send(
      '<html>' +
        '<head>' +
          '<link rel="stylesheet" href="/style.css">' +
          brandVars() +
        '</head>' +
        '<body>' +
          '<div class="wrap">' +
            headerCard('Verify your account', subtitle) +
              '<form action="/verify" method="POST" class="form">' +
                '<input type="email" name="email" placeholder="you@email.com" required>' +
                '<button class="btn btn-primary" type="submit">Send Code</button>' +
              '</form>' +
              '<div class="rules">' +
                '<p><b>⚠️ VPNs / public Wi-Fi are not allowed.</b></p>' +
                '<p><b>🚨 Disposable or fake emails will result in a ban.</b></p>' +
              '</div>' +
            '</div>' +
          '</div>' +
        '</body>' +
      '</html>'
    );
  } catch (e) {
    console.error('[CALLBACK] error:', e);
    return res.status(500).send('Internal error in /callback. Please try again.');
  }
});

/* -----------------------------------------------------------------
   STEP 1: /verify → send email code and show code entry form
------------------------------------------------------------------ */
app.post('/verify', async (req, res) => {
  try {
    const email = (req.body && req.body.email) ? String(req.body.email).trim() : '';
    const discordId = req.cookies.discordId;
    const userAccessToken = req.cookies.userAccessToken;

    if (!email) return res.status(400).send('Please provide an email.');
    if (!discordId || !userAccessToken) return res.status(400).send('Session expired. Go to <a href="/login">/login</a>.');

    // block disposables / invalid
    if (await isDisposableOrInvalidEmail(email)) {
      return res.status(400).send('❌ Invalid email: disposable, automated, or non-receiving addresses are not allowed.');
    }

    // IP policy
    let ip = req.ip;
    const fwd = req.headers['x-forwarded-for'];
    if (fwd && typeof fwd === 'string') ip = fwd.split(',')[0].trim();
    if (await isVPNorProxy(ip)) {
      return res.status(403).send('❌ Verification blocked: VPNs, proxies, and public Wi-Fi are not allowed. Please try again from home Wi-Fi or mobile data.');
    }

    // create/store OTP
    const code = generateCode();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    const pending = readJson(PENDING_JSON).filter(p => p.discordId !== discordId); // drop older
    pending.push({ discordId, email, code, expiresAt, attempts: 0 });
    writeJson(PENDING_JSON, pending);

    // send email
    try { await sendOtpEmail(email, code); }
    catch (e) { console.error('[SMTP] send failed:', e?.message || e); return res.status(500).send('Could not send the code email. Please try again later.'); }

    // show code entry form
    return res.send(
      '<html>' +
        '<head>' +
          '<link rel="stylesheet" href="/style.css">' +
          brandVars() +
        '</head>' +
        '<body>' +
          '<div class="wrap">' +
            headerCard('Enter your code', 'We sent a <b>6-digit code</b> to <b>' + email + '</b>. It expires in 10 minutes.') +
              '<form action="/verify/confirm" method="POST" class="form">' +
                '<input type="text" name="code" placeholder="6-digit code" minlength="6" maxlength="6" pattern="\\d{6}" required>' +
                '<button class="btn btn-primary" type="submit">Verify</button>' +
              '</form>' +
              '<form action="/verify/resend" method="POST" class="form form--inline">' +
                `<input type="hidden" name="email" value="${email}">` +
                '<button class="btn btn-ghost" type="submit">Resend code</button>' +
              '</form>' +
            '</div>' +
          '</div>' +
        '</body>' +
      '</html>'
    );
  } catch (e) {
    console.error('[VERIFY step1] error:', e);
    return res.status(500).send('❌ Error sending code. Please contact staff.');
  }
});

/* -----------------------------------------------------------------
   STEP 1b: /verify/resend → send a fresh code (same email)
------------------------------------------------------------------ */
app.post('/verify/resend', async (req, res) => {
  try {
    const email = (req.body && req.body.email) ? String(req.body.email).trim() : '';
    const discordId = req.cookies.discordId;
    if (!email || !discordId) return res.status(400).send('Session expired. Start again: <a href="/login">/login</a>.');

    const code = generateCode();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    let pending = readJson(PENDING_JSON).filter(p => p.discordId !== discordId);
    pending.push({ discordId, email, code, expiresAt, attempts: 0 });
    writeJson(PENDING_JSON, pending);

    try { await sendOtpEmail(email, code); }
    catch (e) { console.error('[SMTP] resend failed:', e?.message || e); return res.status(500).send('Could not resend code right now.'); }

    return res.send('✅ New code sent. Please check your inbox (and spam). Go back and submit the code.');
  } catch (e) {
    console.error('[VERIFY resend] error:', e);
    return res.status(500).send('Error.');
  }
});

/* -----------------------------------------------------------------
   STEP 2: /verify/confirm (POST) → check code, then roles/joins/log
------------------------------------------------------------------ */
app.post('/verify/confirm', async (req, res) => {
  try {
    const code = (req.body && req.body.code) ? String(req.body.code).trim() : '';
    const discordId = req.cookies.discordId;
    const userAccessToken = req.cookies.userAccessToken;

    if (!code || !/^\d{6}$/.test(code)) return res.status(400).send('Enter a valid 6-digit code.');
    if (!discordId || !userAccessToken) return res.status(400).send('Session expired. Go to <a href="/login">/login</a>.');

    // load pending
    const pending = readJson(PENDING_JSON);
    const idx = pending.findIndex(p => p.discordId === discordId);
    if (idx === -1) return res.status(400).send('No pending code. Start again at <a href="/login">/login</a>.');

    const rec = pending[idx];
    if (Date.now() > rec.expiresAt) {
      pending.splice(idx, 1); writeJson(PENDING_JSON, pending);
      return res.status(400).send('⏱️ Code expired. Please go back and request a new one.');
    }
    if (rec.attempts >= 5) {
      pending.splice(idx, 1); writeJson(PENDING_JSON, pending);
      return res.status(403).send('Too many attempts. Start over at <a href="/login">/login</a>.');
    }

    if (rec.code !== code) {
      rec.attempts += 1; pending[idx] = rec; writeJson(PENDING_JSON, pending);
      return res.status(400).send(`Incorrect code. Attempts left: ${5 - rec.attempts}`);
    }

    // ✅ code correct — consume it
    pending.splice(idx, 1); writeJson(PENDING_JSON, pending);
    const email = rec.email;

    // Join BACKUP server (best-effort)
    let joinedBackup = false;
    if (BACKUP_GUILD_ID) {
      const joinResp = await fetch(`https://discord.com/api/guilds/${BACKUP_GUILD_ID}/members/${discordId}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bot ${BOT_TOKEN}`,
          'Content-Type': 'application/json',
          'User-Agent': 'rp-verifier/1.0 node-fetch',
        },
        body: JSON.stringify({ access_token: userAccessToken })
      });
      joinedBackup = joinResp.ok || joinResp.status === 201 || joinResp.status === 204;
    }

    // Give role in MAIN
    const mainGuild = await client.guilds.fetch(MAIN_GUILD_ID);
    const mainMember = await mainGuild.members.fetch(discordId);
    await mainMember.roles.add(VERIFIED_ROLE_ID_MAIN);

    // Optional role in BACKUP
    if (joinedBackup && VERIFIED_ROLE_ID_BACKUP) {
      const backupGuild = await client.guilds.fetch(BACKUP_GUILD_ID);
      const backupMember = await backupGuild.members.fetch(discordId).catch(() => null);
      if (backupMember) await backupMember.roles.add(VERIFIED_ROLE_ID_BACKUP);
    }

    // DM backup invite
    if (BACKUP_INVITE_URL) {
      try {
        const user = await client.users.fetch(discordId);
        await user.send(
          `✅ You are verified in **${mainGuild.name}**!\n\n` +
          `If the main server is ever unavailable or you leave the backup, here’s your permanent backup invite:\n${BACKUP_INVITE_URL}`
        );
      } catch { /* ignore DM errors */ }
    }

    // Staff log + save
    await sendVerificationLog({ discordId, email });
    try {
      const userObj = await client.users.fetch(discordId).catch(() => null);
      const username = userObj ? `${userObj.username}#${userObj.discriminator ?? '0'}` : discordId;
      saveVerified({ discordId, username, email });
    } catch (e) {
      console.error('[VERIFY save] error:', e);
    }

    // ✅ Redirect to the pretty success page
    return res.redirect(`/verify/confirm?email=${encodeURIComponent(email)}`);
  } catch (e) {
    console.error('[VERIFY step2] error:', e);
    return res.status(500).send('❌ Error verifying. Please contact staff.');
  }
});

/* -----------------------------------------------------------------
   STEP 2: /verify/confirm (GET) → pretty success screen
------------------------------------------------------------------ */
app.get('/verify/confirm', (req, res) => {
  const email = (req.query.email || '').toString();
  const serverLink = MAIN_GUILD_ID
    ? `https://discord.com/channels/${MAIN_GUILD_ID}`
    : 'https://discord.com/channels/@me';

  const subtitle = 'You have successfully verified in <b>' + BRAND.name + '</b>.';

  return res.send(
    '<html>' +
      '<head>' +
        '<link rel="stylesheet" href="/style.css">' +
        brandVars() +
      '</head>' +
      '<body>' +
        '<div class="wrap">' +
          headerCard('Success!', subtitle) +
            '<div class="success-banner">' +
              '<span class="check">✔</span>' +
              '<div>' +
                '<div class="success-title">Verification complete</div>' +
                '<div class="success-sub">Email ' + (email ? ('<b>' + email + '</b>') : '') + ' confirmed.</div>' +
              '</div>' +
            '</div>' +
            `<a class="btn btn-primary btn-wide" href="${serverLink}">Open Discord</a>` +
            '<p class="hint">If the button doesn’t open the server, switch back to Discord — your access is unlocked.</p>' +
          '</div>' +
        '</div>' +
      '</body>' +
    '</html>'
  );
});

/* -----------------------------------------------------------------
   Admin route: download CSV of verified users (now protected)
------------------------------------------------------------------ */
app.get('/admin/verified.csv', requireAuth, (req, res) => {
  try {
    ensureStore();
    const rows = readJson(VERIFIED_JSON);
    const header = 'discordId,username,email,verifiedAt';
    const csv = [
      header,
      ...rows.map(r => [r.discordId, r.username, r.email, r.verifiedAt]
        .map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))
    ].join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="verified.csv"');
    res.send(csv);
  } catch (e) {
    console.error('[ADMIN] export csv error:', e);
    res.status(500).send('Could not generate CSV');
  }
});

/* -----------------------------------
   Test route to verify logging works
----------------------------------- */
app.get('/_testlog', requireAuth, async (req, res) => {
  try {
    await sendVerificationLog({ discordId: '000000000000000000', email: 'test@example.com' });
    res.status(200).send('Sent test log to LOG_CHANNEL_ID.');
  } catch (e) {
    res.status(500).send('Failed to send test log. Check server logs.');
  }
});

/* ----------------------------
   Start server
----------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🌍 Server running on http://localhost:${PORT}`);
  console.log(`🔑 Start here:   http://localhost:${PORT}/login`);
});
