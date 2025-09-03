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

// ✅ Rate-limit /verify to avoid abuse
app.use('/verify', rateLimit({ windowMs: 2 * 60 * 1000, max: 20 }));

const {
  CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, TOKEN: BOT_TOKEN,
  MAIN_GUILD_ID, BACKUP_GUILD_ID,
  VERIFIED_ROLE_ID_MAIN, VERIFIED_ROLE_ID_BACKUP,
  LOG_CHANNEL_ID, BACKUP_INVITE_URL,
  ADMIN_USER, ADMIN_PASS
} = process.env;

// ✅ Data storage setup (supports Render disk via DATA_DIR)
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const VERIFIED_JSON = path.join(DATA_DIR, 'verified.json');

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(VERIFIED_JSON)) fs.writeFileSync(VERIFIED_JSON, '[]', 'utf8');
}

function saveVerified({ discordId, username, email }) {
  ensureStore();
  const now = new Date().toISOString();
  const arr = JSON.parse(fs.readFileSync(VERIFIED_JSON, 'utf8'));
  arr.push({ discordId, username, email, verifiedAt: now });
  fs.writeFileSync(VERIFIED_JSON, JSON.stringify(arr, null, 2), 'utf8');
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
// Base list (lowercased)
const DISPOSABLE_SET = new Set(disposableList.map(d => d.toLowerCase()));

// Extra domains via env (comma-separated), e.g. "tempmail.email,noidem.com"
const EXTRA_DISPOSABLE = (process.env.EXTRA_DISPOSABLE_DOMAINS || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);
for (const d of EXTRA_DISPOSABLE) DISPOSABLE_SET.add(d);

// MX host pattern blocks (known disposable providers)
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

// Allow adding new MX host patterns quickly via env (pipe-separated regexes)
// Example value:  '(^|\\.)noidem\\.com$|(^|\\.)mx-noidem\\.com$'
const EXTRA_MX_BLOCK = (process.env.EXTRA_DISPOSABLE_MX || '')
  .split('|')
  .map(s => s.trim())
  .filter(Boolean);
for (const pat of EXTRA_MX_BLOCK) {
  try { MX_BLOCK_PATTERNS.push(new RegExp(pat, 'i')); } catch {}
}

// Helper: get domain host + registrable root (sub.a.b.c -> b.c)
function getDomains(email = '') {
  const at = email.lastIndexOf('@');
  if (at < 0) return {};
  const host = email.slice(at + 1).toLowerCase().trim();
  const info = parse(host); // { domain, hostname, ... }
  return { host, root: info.domain || host };
}

async function isDisposableOrInvalidEmail(email = '') {
  // Basic shape: simple sanity
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return true;

  const { host, root } = getDomains(email);
  if (!host || !root) return true;

  // Direct domain/root block
  if (DISPOSABLE_SET.has(host) || DISPOSABLE_SET.has(root)) return true;

  // DNS MX check: no MX = invalid
  let mx;
  try {
    mx = await dns.resolveMx(host);
    if (!mx || mx.length === 0) return true;
  } catch {
    return true; // DNS lookup failed -> invalid
  }

  // MX hostname pattern block (provider-based)
  const mxHosts = mx.map(r => (r && r.exchange ? String(r.exchange).toLowerCase() : ''));
  for (const h of mxHosts) {
    if (!h) continue;
    if (MX_BLOCK_PATTERNS.some(rx => rx.test(h))) {
      return true;
    }
  }

  return false; // looks good
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
    if (!ip || ip === '::1' || ip === '127.0.0.1') return false; // skip localhost
    const resp = await axios.get(`http://ip-api.com/json/${ip}?fields=proxy,hosting,mobile,query`);
    const d = resp.data;
    return d.proxy === true || d.hosting === true; // block VPN/datacenter
  } catch (e) {
    console.error('[VPN CHECK] error:', e?.message || e);
    return false; // don’t block if API fails
  }
}

/* -----------------------------------------------------------------
   Helper: exchange auth code for token with retries/backoff
------------------------------------------------------------------ */
async function exchangeCodeForToken({ code, clientId, clientSecret, redirectUri, fetchImpl }) {
  const fetchFn = fetchImpl || fetch;
  const form = () => new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
  });

  const maxAttempts = 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const resp = await fetchFn('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'rp-verifier/1.0 (+https://discord.com) node-fetch',
      },
      body: form(),
    });

    if (resp.ok) {
      return await resp.json();
    }

    if (resp.status === 429 && attempt < maxAttempts) {
      const ra = Number(resp.headers.get('retry-after')) || 2;
      console.warn(`[CALLBACK] 429 token exchange. Retrying in ${ra}s (attempt ${attempt}/${maxAttempts})`);
      await new Promise(r => setTimeout(r, ra * 1000));
      continue;
    }

    const txt = await resp.text().catch(() => '');
    const err = new Error(`token exchange failed: ${resp.status} ${txt}`);
    err.status = resp.status;
    throw err;
  }

  throw new Error('token exchange failed after retries.');
}

/* -----------------------------------
   LOGGING HELPERS (fixes your missing log)
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

    // Try embed first
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

    const msg = await ch.send(payload).catch(err => {
      console.error('[LOG] embed send failed:', err?.message || err);
      return null;
    });

    // Plain-text fallback if embeds aren’t allowed
    if (!msg) {
      await ch.send(`✅ New verification: <@${discordId}> (${discordId}) | ${email || '—'}`).catch(err => {
        console.error('[LOG] plaintext send failed:', err?.message || err);
      });
    }
  } catch (e) {
    console.error('[LOG] sendVerificationLog error:', e?.message || e);
  }
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

    // verify OAuth state
    if (!req.query.state || req.query.state !== req.cookies.oauth_state) {
      return res.status(400).send('OAuth state mismatch. Please start again at <a href="/login">/login</a>.');
    }

    // token exchange with retry/backoff
    let access_token;
    try {
      const tok = await exchangeCodeForToken({
        code,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        redirectUri: REDIRECT_URI,
        fetchImpl: fetch,
      });
      access_token = tok.access_token;
    } catch (err) {
      console.error('[CALLBACK]', err?.message || err);
      const msg = String(err?.message || '');
      if (msg.includes('429')) {
        return res
          .status(429)
          .send('We are being rate-limited by Discord. Please wait ~60 seconds and try again via <a href="/login">/login</a>.');
      }
      return res
        .status(400)
        .send('OAuth failed. Please try again via <a href="/login">/login</a>.');
    }

    if (!access_token) {
      return res.status(400).send('No access_token. Try <a href="/login">/login</a> again.');
    }

    // Fetch user
    const meResp = await fetch('https://discord.com/api/users/@me', {
      headers: {
        Authorization: `Bearer ${access_token}`,
        'User-Agent': 'rp-verifier/1.0 (+https://discord.com) node-fetch',
      }
    });
    if (!meResp.ok) {
      const t = await meResp.text().catch(() => '');
      console.error('[CALLBACK] user fetch failed:', meResp.status, t);
      return res.status(400).send('Could not fetch user. Try <a href="/login">/login</a> again.');
    }
    const me = await meResp.json();

    res.cookie('discordId', me.id, cookieOpts);
    res.cookie('userAccessToken', access_token, cookieOpts);

    return res.send(`
      <html>
        <head>
          <link rel="stylesheet" href="/style.css">
        </head>
        <body>
          <div class="container">
            <img src="https://cdn.discordapp.com/avatars/${me.id}/${me.avatar}.png" 
                 alt="Avatar" style="width:80px;height:80px;border-radius:50%;margin-bottom:15px;">
            <h2>Verify your account</h2>
            <p>Welcome <b>${me.username}</b>! Please enter your email to continue:</p>
            <form action="/verify" method="POST">
              <input type="email" name="email" placeholder="Enter your email" required>
              <button type="submit">Verify</button>
            </form>

            <p class="note note--important">
              ⚠️ <b>Use only home Wi-Fi or mobile data. VPNs / public Wi-Fi are not allowed.</b>
            </p>
            <p class="note note--important">
              🚨 <b>Automated, disposable, or fake emails will result in a ban.</b>
            </p>
          </div>
        </body>
      </html>
    `);
  } catch (e) {
    console.error('[CALLBACK] error:', e);
    return res.status(500).send('Internal error in /callback. Please try again.');
  }
});

/* -----------------------------------------------------------------
   /verify → auto-join backup + add roles + DM + log + save file
------------------------------------------------------------------ */
app.post('/verify', async (req, res) => {
  try {
    const email = (req.body && req.body.email) ? String(req.body.email).trim() : '';
    const discordId = req.cookies.discordId;
    const userAccessToken = req.cookies.userAccessToken;

    if (!email) return res.status(400).send('Please provide an email.');
    if (!discordId || !userAccessToken) return res.status(400).send('Session expired. Go to <a href="/login">/login</a>.');

    // ✅ Strong disposable/invalid email check
    if (await isDisposableOrInvalidEmail(email)) {
      return res.status(400).send('❌ Invalid email: disposable, automated, or non-receiving addresses are not allowed.');
    }

    // ✅ VPN / Proxy check
    let ip = req.ip;
    const fwd = req.headers['x-forwarded-for'];
    if (fwd && typeof fwd === 'string') ip = fwd.split(',')[0].trim();
    const blocked = await isVPNorProxy(ip);
    if (blocked) {
      return res.status(403).send(
        "❌ Verification blocked: VPNs, proxies, and public Wi-Fi are not allowed. " +
        "Please try again from home Wi-Fi or mobile data."
      );
    }

    // A) Auto-join BACKUP server (best-effort)
    let joinedBackup = false;
    if (BACKUP_GUILD_ID) {
      const joinResp = await fetch(`https://discord.com/api/guilds/${BACKUP_GUILD_ID}/members/${discordId}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bot ${BOT_TOKEN}`,
          'Content-Type': 'application/json',
          'User-Agent': 'rp-verifier/1.0 (+https://discord.com) node-fetch',
        },
        body: JSON.stringify({ access_token: userAccessToken })
      });
      joinedBackup = joinResp.ok || joinResp.status === 201 || joinResp.status === 204;
    }

    // B) Add Verified role in MAIN server
    const mainGuild = await client.guilds.fetch(MAIN_GUILD_ID);
    const mainMember = await mainGuild.members.fetch(discordId);
    await mainMember.roles.add(VERIFIED_ROLE_ID_MAIN);

    // C) Optional: add Verified role in BACKUP server
    if (joinedBackup && VERIFIED_ROLE_ID_BACKUP) {
      const backupGuild = await client.guilds.fetch(BACKUP_GUILD_ID);
      const backupMember = await backupGuild.members.fetch(discordId).catch(() => null);
      if (backupMember) await backupMember.roles.add(VERIFIED_ROLE_ID_BACKUP);
    }

    // D) DM backup invite link
    if (BACKUP_INVITE_URL) {
      try {
        const user = await client.users.fetch(discordId);
        await user.send(
          `✅ You are verified in **${mainGuild.name}**!\n\n` +
          `If the main server is ever unavailable or you leave the backup, here’s your permanent backup invite:\n${BACKUP_INVITE_URL}`
        );
      } catch (e) {
        console.warn('[VERIFY] Could not DM user.');
      }
    }

    // E) Log verification to staff channel  🔔 (new helper)
    await sendVerificationLog({ discordId, email });

    // F) Save to verified.json
    try {
      const userObj = await client.users.fetch(discordId).catch(() => null);
      const username = userObj ? `${userObj.username}#${userObj.discriminator ?? '0'}` : discordId;
      saveVerified({ discordId, username, email });
    } catch (e) {
      console.error('[VERIFY] failed to save verified record:', e);
    }

    return res.send(`✅ Verified! Email <b>${email}</b> recorded. You now have access to the server.`);
  } catch (e) {
    console.error('[VERIFY] error:', e);
    return res.status(500).send('❌ Error verifying. Please contact staff.');
  }
});

/* -----------------------------------------------------------------
   Admin route: download CSV of verified users (now protected)
------------------------------------------------------------------ */
app.get('/admin/verified.csv', requireAuth, (req, res) => {
  try {
    ensureStore();
    const rows = JSON.parse(fs.readFileSync(VERIFIED_JSON, 'utf8'));
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
const PORT = process.env.PORT || 3000;   // ✅ deployment-ready port
app.listen(PORT, () => {
  console.log(`🌍 Server running on http://localhost:${PORT}`);
  console.log(`🔑 Start here:   http://localhost:${PORT}/login`);
});
