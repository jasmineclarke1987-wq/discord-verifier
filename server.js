require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');            // if Node < 18, installed as node-fetch@2
const client = require('./bot');
const fs = require('fs');
const path = require('path');
const axios = require('axios');                 // ✅ added axios

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('trust proxy', true);

// ✅ Serve static files (style.css in /public folder)
app.use(express.static('public'));

const {
  CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, TOKEN: BOT_TOKEN,
  MAIN_GUILD_ID, BACKUP_GUILD_ID,
  VERIFIED_ROLE_ID_MAIN, VERIFIED_ROLE_ID_BACKUP,
  LOG_CHANNEL_ID, BACKUP_INVITE_URL
} = process.env;

// ✅ Data storage setup
const DATA_DIR = path.join(__dirname, 'data');
const VERIFIED_JSON = path.join(DATA_DIR, 'verified.json');

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
  if (!fs.existsSync(VERIFIED_JSON)) fs.writeFileSync(VERIFIED_JSON, '[]', 'utf8');
}

function saveVerified({ discordId, username, email }) {
  ensureStore();
  const now = new Date().toISOString();
  const arr = JSON.parse(fs.readFileSync(VERIFIED_JSON, 'utf8'));
  arr.push({ discordId, username, email, verifiedAt: now });
  fs.writeFileSync(VERIFIED_JSON, JSON.stringify(arr, null, 2), 'utf8');
}

// ✅ VPN / proxy detector using ip-api.com
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
        // UA helps some Cloudflare edges identify the client cleanly
        'User-Agent': 'rp-verifier/1.0 (+https://discord.com) node-fetch',
      },
      body: form(),
    });

    if (resp.ok) {
      return await resp.json();
    }

    // On 429, back off and retry
    if (resp.status === 429 && attempt < maxAttempts) {
      const ra = Number(resp.headers.get('retry-after')) || 2;
      console.warn(`[CALLBACK] 429 token exchange. Retrying in ${ra}s (attempt ${attempt}/${maxAttempts})`);
      await new Promise(r => setTimeout(r, ra * 1000));
      continue;
    }

    // Any other error: capture details and throw
    const txt = await resp.text().catch(() => '');
    const err = new Error(`token exchange failed: ${resp.status} ${txt}`);
    err.status = resp.status;
    throw err;
  }

  throw new Error('token exchange failed after retries.');
}

/* -----------------------------------
   /health → simple warm-up/monitor
----------------------------------- */
app.get('/health', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.status(200).send('ok');
});

/* -----------------------------------
   /login → send user to authorize
----------------------------------- */
app.get('/login', (req, res) => {
  const url = 'https://discord.com/api/oauth2/authorize'
    + `?client_id=${encodeURIComponent(CLIENT_ID)}`
    + `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`
    + `&response_type=code`
    + `&scope=${encodeURIComponent('identify guilds.join')}`;
  res.redirect(url);
});

/* ----------------------------------------------------------
   /callback → exchange code, store cookies, show email form
---------------------------------------------------------- */
app.get('/callback', async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send('No code. Start again: <a href="/login">/login</a>');

    // ✅ robust token exchange with retry/backoff
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

    res.cookie('discordId', me.id, { httpOnly: true });
    res.cookie('userAccessToken', access_token, { httpOnly: true });

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
            <p class="note">⚠️ Use only home Wi-Fi or mobile data. VPNs / public Wi-Fi are not allowed.</p>
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

    // A) Auto-join BACKUP server
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

    // E) Log verification to staff channel
    if (LOG_CHANNEL_ID) {
      try {
        const logCh = await client.channels.fetch(LOG_CHANNEL_ID);
        await logCh.send({
          embeds: [{
            title: '✅ User Verified',
            color: 0x57F287,
            fields: [
              { name: 'User', value: `<@${discordId}> (${discordId})` },
              { name: 'Email', value: email }
            ],
            timestamp: new Date()
          }]
        });
      } catch (e) {
        console.error('[VERIFY] Failed to send log:', e);
      }
    }

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
   Admin route: download CSV of verified users
------------------------------------------------------------------ */
app.get('/admin/verified.csv', (req, res) => {
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

/* ----------------------------
   Start server
----------------------------- */
const PORT = process.env.PORT || 3000;   // ✅ deployment-ready port
app.listen(PORT, () => {
  console.log(`🌍 Server running on http://localhost:${PORT}`);
  console.log(`🔑 Start here:   http://localhost:${PORT}/login`);
});
