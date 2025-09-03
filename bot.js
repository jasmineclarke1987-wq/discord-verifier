require('dotenv').config();

const {
  Client,
  GatewayIntentBits,
  Partials,
  SlashCommandBuilder,
  EmbedBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  PermissionsBitField,
} = require('discord.js');

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers],
  partials: [Partials.GuildMember],
});

/* -------- Verify URL helper -----------------------------------
   Prefer an explicit VERIFY_URL env (recommended).
   Otherwise, if REDIRECT_URI ends with /callback, switch it to /login.
   Last-resort hardcoded fallback keeps you working.
---------------------------------------------------------------- */
const VERIFY_URL =
  process.env.VERIFY_URL ||
  (process.env.REDIRECT_URI?.includes('/callback')
    ? process.env.REDIRECT_URI.replace('/callback', '/login')
    : 'https://rp-verifier.onrender.com/login');

client.once('ready', async () => {
  console.log(`✅ Bot logged in as ${client.user.tag}`);

  // Register /setup-verify globally (simple, one-command registration)
  try {
    await client.application.commands.create(
      new SlashCommandBuilder()
        .setName('setup-verify')
        .setDescription('Post the verification panel in the current channel.')
        .toJSON()
    );
    console.log('✅ /setup-verify command registered');
  } catch (e) {
    console.error('❌ Failed to register /setup-verify:', e);
  }
});

// Handle the slash command
client.on('interactionCreate', async (interaction) => {
  try {
    if (!interaction.isChatInputCommand()) return;
    if (interaction.commandName !== 'setup-verify') return;

    // Basic permission gate: Admin / Manage Guild / Manage Channels
    const member = interaction.member;
    const hasPerm =
      member.permissions.has(PermissionsBitField.Flags.Administrator) ||
      member.permissions.has(PermissionsBitField.Flags.ManageGuild) ||
      member.permissions.has(PermissionsBitField.Flags.ManageChannels);

    if (!hasPerm) {
      return interaction.reply({
        content: 'You need **Administrator / Manage** permissions to use this.',
        ephemeral: true,
      });
    }

    // Build the pretty panel
    const embed = new EmbedBuilder()
      .setColor(0x5865f2)
      .setTitle('Verify')
      .setDescription('To get access to the server, click the button below to verify your account.')
      // Optional: replace with your server icon URL, or comment out this line
      // .setThumbnail('https://cdn.discordapp.com/icons/YOUR_SERVER_ID/YOUR_ICON_HASH.png?size=128')
      .setFooter({ text: 'Safe • Secure • Quick' });

    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setLabel('Verify')
        .setStyle(ButtonStyle.Link)
        .setURL(VERIFY_URL)
        .setEmoji('🛡️') // optional
    );

    await interaction.reply({ embeds: [embed], components: [row] });
  } catch (e) {
    console.error('setup-verify error:', e);
    if (interaction.replied || interaction.deferred) {
      await interaction.followUp({
        content: 'Failed to post panel. Check my permissions in this channel.',
        ephemeral: true,
      });
    } else {
      await interaction.reply({
        content: 'Failed to post panel. Check my permissions in this channel.',
        ephemeral: true,
      });
    }
  }
});

client.login(process.env.TOKEN);

module.exports = client;
