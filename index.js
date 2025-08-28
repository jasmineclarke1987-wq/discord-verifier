require('dotenv').config();
const express = require('express');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { Client, GatewayIntentBits, Partials } = require('discord.js');

const app = express();
const PORT = 3000;

// Parse HTML form posts (for the email field)
app.use(express.urlencoded({ extended: true }));

// CSV storage
const CSV_PATH = path.join(__dirname, 'verifications.csv');
function appendVerificationRow({ discordId, username, email }) {
  const ts = new Date().toISOString();
  const header = 'timestamp,discord_id,username,email\n';
  if (!fs.existsSync(CSV_PATH)) fs.writeFileSync(CSV_PATH, header);

  // basic CSV escaping
  const esc = (v) => String(v ?? '').replace(/"/g, '""');
  const row = `"${ts}","${esc(discordId)}","${esc(username)}","${esc(email)}"\n`;
  fs.appendFileSync(CSV_PATH, row);
}

// Discord client
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMembers,     // needed to fetch members / add roles
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
  partials: [Partials.GuildMember],
});

client.once('ready', () => {
  console.log(`✅ Logged in as ${client.user.tag}`);
});

// Optional helper command inside Discord
client.on('messageCreate', (message) => {
  if (message.content === '!verify') {
    message.reply('Verify here: http://localhost:3000/login');
  }
});

// Health check
app.get('/', (_req, res) => res.send('OK'));

// STEP A: Send user to Discord OAuth
app.get('/login', (_req, res) => {
  const authUrl =
    `https://discord.com/oauth2/authorize?client_id=${process.env.CLIENT_ID}` +
    `&response_type=code` +
    `&redirect_uri=${encodeURIComponent(process.env.REDIRECT_URI)}` +
    `&scope=identify%20guilds.join`;
  res.redirect(authUrl);
});

// STEP B: OAuth callback → exchange code → get user → show email form
app.get('/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('No code provided.');

  try {
    // Exchange auth code for user access token
    const tokenRes = await axios.post(
      'https://discord.com/api/oauth2/token',
      new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.REDIRECT_URI,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const accessToken = tokenRes.data.access_token;

    // Get user identity
    const userRes = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const user = userRes.data;

    // Render simple email form (posts to /verify)
    res.send(`
      <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;max-width:420px;margin:48px auto">
        <h2>Welcome, ${user.username}</h2>
        <p>Enter your email to finish verification:</p>
        <form method="POST" action="/verify">
          <input type="hidden" name="user_id" value="${user.id}" />
          <input type="hidden" name="username" value="${user.username}" />
          <input type="hidden" name="access_token" value="${accessToken}" />
          <input type="email" name="email" required placeholder="you@example.com"
                 style="width:100%;padding:10px;border:1px solid #ccc;border-radius:8px;margin:8px 0" />
          <label style="display:block;margin:8px 0 14px 0;font-size:12px;color:#555">
            <input type="checkbox" required /> I consent to my email being stored for server verification purposes.
          </label>
          <button type="submit" style="padding:10px 14px;border:0;border-radius:8px;background:#5865F2;color:white;cursor:pointer">
            Finish Verification
          </button>
        </form>
      </div>
    `);
  } catch (err) {
    console.error('OAuth error:', err.response?.data || err.message);
    res.status(500).send('Verification failed at login step.');
  }
});

// STEP C: Handle email → ensure in main guild → add role → optional backup join + save/log
app.post('/verify', async (req, res) => {
  try {
    const { user_id, username, access_token, email } = req.body || {};
    if (!user_id || !access_token || !email) {
      return res.status(400).send('Missing data; please go back and try again.');
    }

    // Helper to guilds.join a user to a guild using their access token
    const joinGuild = async (guildId) => {
      await axios.put(
        `https://discord.com/api/guilds/${guildId}/members/${user_id}`,
        { access_token },
        {
          headers: {
            Authorization: `Bot ${process.env.TOKEN}`,
            'Content-Type': 'application/json',
          },
        }
      );
    };

    // Ensure the user is in your MAIN guild (join if needed)
    const mainGuild = await client.guilds.fetch(process.env.GUILD_ID);
    let member;
    try {
      member = await mainGuild.members.fetch(user_id);
    } catch {
      await joinGuild(process.env.GUILD_ID);            // join main
      member = await mainGuild.members.fetch(user_id);  // re-fetch
    }

    // Add the Verified role
    await member.roles.add(process.env.VERIFIED_ROLE_ID);

    // Optional: join backup guild as well
    if (process.env.BACKUP_GUILD_ID && process.env.BACKUP_GUILD_ID.trim().length) {
      try {
        await joinGuild(process.env.BACKUP_GUILD_ID);
      } catch (e) {
        console.warn('Backup guild join failed (continuing):', e.response?.data || e.message);
      }
    }

    // 💾 Save to CSV
    appendVerificationRow({ discordId: user_id, username, email });

    // 📣 Optional: log to a private Discord channel
    if (process.env.LOG_CHANNEL_ID) {
      try {
        const ch = await client.channels.fetch(process.env.LOG_CHANNEL_ID);
        if (ch) await ch.send(`✅ New verification: <@${user_id}> | **${email}**`);
      } catch (e) {
        console.warn('Log channel send failed:', e.message);
      }
    }

    console.log(`✅ Verified ${user_id} — ${username} — ${email}`);
    res.send(`✅ Verified! Your email (${email}) was recorded and your role was assigned.`);
  } catch (err) {
    console.error('Verify error:', err.response?.data || err.message);
    res.status(500).send('Could not complete verification.');
  }
});

// Simple download route if you want to pull the CSV in the browser
app.get('/export.csv', (_req, res) => {
  if (!fs.existsSync(CSV_PATH)) return res.status(404).send('No data yet.');
  res.sendFile(CSV_PATH);
});

// Start the web server
app.listen(PORT, () => console.log(`🌍 Web server running at http://localhost:${PORT}`));

// Login the bot
client.login(process.env.TOKEN);
