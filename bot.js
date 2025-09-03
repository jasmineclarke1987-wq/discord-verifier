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
   Prefer an explicit VERIFY_URL env.
   Otherwise, if REDIRECT_URI ends with /callback, switch it to /login.
   Fallback keeps you working.
---------------------------------------------------------------- */
const VERIFY_URL =
  process.env.VERIFY_URL ||
  (process.env.REDIRECT_URI?.includes('/callback')
    ? process.env.REDIRECT_URI.replace('/callback', '/login')
    : 'https://rp-verifier.onrender.com/login');

// Slash command definitions
const setupVerifyCommand = new SlashCommandBuilder()
  .setName('setup-verify')
  .setDescription('Post the verification panel in this channel.');

const pingCommand = new SlashCommandBuilder()
  .setName('rp-ping')
  .setDescription('Test command to confirm slash commands are working.');

client.once('ready', async () => {
  console.log(`✅ Bot logged in as ${client.user.tag}`);

  // Register commands PER-GUILD (instant availability)
  try {
    const guilds = await client.guilds.fetch();
    for (const [id] of guilds) {
      const g = await client.guilds.fetch(id);
      await g.commands.create(setupVerifyCommand);
      await g.commands.create(pingCommand);
      console.log(`🛠️ Registered commands in ${g.name} (${g.id})`);
    }
  } catch (e) {
    console.error('❌ Command registration failed:', e);
  }
});

// Handle slash commands
client.on('interactionCreate', async (interaction) => {
  try {
    if (!interaction.isChatInputCommand()) return;

    if (interaction.commandName === 'rp-ping') {
      return interaction.reply({ content: '🏓 Slash commands are working!', ephemeral: true });
    }

    if (interaction.commandName === 'setup-verify') {
      // Permission gate: admins or managers
      const member = interaction.member;
      const hasPerm =
        member?.permissions?.has(PermissionsBitField.Flags.Administrator) ||
        member?.permissions?.has(PermissionsBitField.Flags.ManageGuild) ||
        member?.permissions?.has(PermissionsBitField.Flags.ManageChannels);

      if (!hasPerm) {
        return interaction.reply({
          content: 'You need **Administrator / Manage** permissions to use this.',
          ephemeral: true,
        });
      }

      const embed = new EmbedBuilder()
        .setColor(0x5865f2)
        .setTitle('Verify')
        .setDescription('To get access to the server, click the button below to verify your account.')
        .setFooter({ text: 'Safe • Secure • Quick' });
        // Optional thumbnail:
        // .setThumbnail('https://cdn.discordapp.com/icons/YOUR_SERVER_ID/YOUR_ICON_HASH.png?size=128')

      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder()
          .setLabel('Verify')
          .setStyle(ButtonStyle.Link)
          .setURL(VERIFY_URL)
          .setEmoji('🛡️') // optional
      );

      await interaction.reply({ embeds: [embed], components: [row] });
    }
  } catch (e) {
    console.error('⚠️ interaction error:', e);
    const msg = 'I couldn’t send the panel here. Make sure I can **View Channel, Send Messages, and Embed Links**.';
    if (interaction.replied || interaction.deferred) {
      await interaction.followUp({ content: msg, ephemeral: true }).catch(() => {});
    } else {
      await interaction.reply({ content: msg, ephemeral: true }).catch(() => {});
    }
  }
});

client.login(process.env.TOKEN);

module.exports = client;
