require('dotenv').config();
const { Client, GatewayIntentBits, Partials } = require('discord.js');

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers],
  partials: [Partials.GuildMember],
});

client.once('ready', () => {
  console.log(`✅ Bot logged in as ${client.user.tag}`);
});

client.login(process.env.TOKEN);

module.exports = client;
