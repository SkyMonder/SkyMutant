const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const cheerio = require('cheerio');

const app = express();
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization,x-upload-token');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000;
const ADMIN_LOGIN = process.env.ADMIN_LOGIN || 'SkyMonder';
const CLIENT_SECRET = "BLx5Vp7U1c8dR2mQkG4fJ6yA9tC3bF0zH7iL2nM5oP8=";
const CLIENT_KEY = Buffer.from(CLIENT_SECRET, 'base64');
let STORAGE_KEY = Buffer.from(process.env.STORAGE_KEY_HEX || crypto.randomBytes(32).toString('hex'), 'hex');

// ---------- Файловая БД ----------
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
function dbPut(bucket, key, data) {
  const dir = path.join(DATA_DIR, bucket);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, key + '.json'), JSON.stringify(data));
}
function dbGet(bucket, key) {
  const file = path.join(DATA_DIR, bucket, key + '.json');
  if (!fs.existsSync(file)) return null;
  try { return JSON.parse(fs.readFileSync(file, 'utf-8')); } catch (e) { return null; }
}
function dbList(bucket) {
  const dir = path.join(DATA_DIR, bucket);
  try {
    if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); return []; }
    return fs.readdirSync(dir).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5));
  } catch (e) { return []; }
}
function dbDelete(bucket, key) {
  const file = path.join(DATA_DIR, bucket, key + '.json');
  if (fs.existsSync(file)) fs.unlinkSync(file);
}

// ---------- Шифрование ----------
function encryptForStorage(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', STORAGE_KEY, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const tag = cipher.getAuthTag().toString('base64');
  return JSON.stringify({ iv: iv.toString('base64'), data: encrypted, tag });
}
function decryptFromStorage(encryptedObj) {
  try {
    const { iv, data, tag } = JSON.parse(encryptedObj);
    const decipher = crypto.createDecipheriv('aes-256-gcm', STORAGE_KEY, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    let decrypted = decipher.update(data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) { return null; }
}
async function decryptClientPayload(combinedBase64) {
  const combined = Buffer.from(combinedBase64, 'base64');
  const iv = combined.slice(0, 12);
  const encrypted = combined.slice(12);
  const decipher = crypto.createDecipheriv('aes-256-gcm', CLIENT_KEY, iv);
  const authTag = encrypted.slice(-16);
  const data = encrypted.slice(0, -16);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(data, null, 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}
async function encryptClientResponse(plainObj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', CLIENT_KEY, iv);
  let encrypted = cipher.update(JSON.stringify(plainObj), 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const authTag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, Buffer.from(encrypted, 'base64'), authTag]);
  return combined.toString('base64');
}

// ---------- Загрузка файлов ----------
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + '_' + Math.random().toString(36).slice(2,8) + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 10*1024*1024 } });
const uploadTokens = {};

// ========== Healthix ==========
app.get('/healthix', (req, res) => res.json({ status: 'ok' }));

// ========== SkyCounter ==========
const SITES = ['skycitadel.onrender.com'];
app.get('/checkvizit', (req, res) => {
  const site = req.query.site;
  if (!site) return res.status(400).json({ error: 'Missing site' });
  if (!SITES.includes(site)) return res.status(403).json({ error: 'Site not allowed' });
  const today = new Date().toISOString().split('T')[0];
  const visits = dbGet('visits', today) || [];
  if (!visits.includes(site)) { visits.push(site); dbPut('visits', today, visits); return res.json({ status: 'ok', site, date: today }); }
  res.json({ status: 'already_exists', site, date: today });
});

// ========== SkyID ==========
app.post('/register', async (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'No data' });
  const payload = await decryptClientPayload(data);
  const { login, password } = payload;
  if (!login || !password) return res.status(400).json({ error: 'login/password required' });
  if (dbGet('skyid_users', login)) return res.status(409).json({ error: 'User exists' });
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  const skyid = 'sky_' + crypto.randomBytes(4).toString('hex');
  const token = crypto.randomBytes(32).toString('hex');
  dbPut('skyid_users', login, { skyid, salt, hash, token, name: login, avatar: '', status: 'online' });
  const answer = { skyid, token };
  const enc = await encryptClientResponse(answer);
  res.json({ data: enc });
});
app.post('/login', async (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'No data' });
  const payload = await decryptClientPayload(data);
  const { login, password } = payload;
  if (!login || !password) return res.status(400).json({ error: 'login/password required' });
  const user = dbGet('skyid_users', login);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const hash = crypto.pbkdf2Sync(password, user.salt, 100000, 64, 'sha512').toString('hex');
  if (hash !== user.hash) return res.status(401).json({ error: 'Invalid password' });
  const token = crypto.randomBytes(32).toString('hex');
  user.token = token;
  dbPut('skyid_users', login, user);
  const answer = { skyid: user.skyid, token };
  const enc = await encryptClientResponse(answer);
  res.json({ data: enc });
});
app.get('/me', (req, res) => {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const users = dbList('skyid_users');
  for (const login of users) {
    const user = dbGet('skyid_users', login);
    if (user && user.token === auth) return res.json({ skyid: user.skyid, login });
  }
  res.status(401).json({ error: 'Invalid token' });
});

// ========== Чат-регистрация ==========
app.post('/chat/register', (req, res) => {
  const { login, salt } = req.body;
  if (!login || !salt) return res.status(400).json({ error: 'login and salt required' });
  if (dbGet('chat_users', login)) return res.status(409).json({ error: 'User exists' });
  dbPut('chat_users', login, { salt, name: login, avatar: '', status: 'online' });
  res.json({ ok: true });
});
app.get('/chat/login_salt', (req, res) => {
  const login = req.query.login;
  if (!login) return res.status(400).json({ error: 'login required' });
  const user = dbGet('chat_users', login);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ salt: user.salt });
});

// ========== Погода ==========
app.post('/api/weather', async (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'No data' });
  const payload = await decryptClientPayload(data);
  const city = payload.city;
  if (!city) return res.status(400).json({ error: 'City required' });
  const weatherRes = await axios.get(`https://wttr.in/${encodeURIComponent(city)}?format=j1`, { timeout: 8000 });
  const current = weatherRes.data.current_condition[0];
  const answer = { temp: current.temp_C, desc: current.weatherDesc[0].value, city };
  const enc = await encryptClientResponse(answer);
  res.json({ data: enc });
});

// ========== Объявления ==========
app.get('/announcements', async (req, res) => {
  const keys = dbList('announcements');
  const list = keys.map(k => dbGet('announcements', k)).filter(Boolean).sort((a,b) => b.created - a.created);
  const enc = await encryptClientResponse(list);
  res.json({ data: enc });
});
app.post('/announcements', async (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'No data' });
  const payload = await decryptClientPayload(data);
  const text = payload.text;
  if (!text) return res.status(400).json({ error: 'Text required' });
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const users = dbList('skyid_users');
  let isAdmin = false;
  for (const login of users) {
    const u = dbGet('skyid_users', login);
    if (u && u.token === auth && u.login === ADMIN_LOGIN) { isAdmin = true; break; }
  }
  if (!isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const ann = { id: 'ann_' + Date.now(), text, created: Date.now() };
  dbPut('announcements', ann.id, ann);
  const enc = await encryptClientResponse({ ok: true });
  res.json({ data: enc });
});

// ========== Прокси ==========
app.get('/proxy', async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).send('URL required');
  try {
    const response = await axios.get(targetUrl, {
      responseType: 'text',
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
      maxRedirects: 5, timeout: 15000
    });
    delete response.headers['x-frame-options'];
    delete response.headers['content-security-policy'];
    let html = response.data;
    const $ = cheerio.load(html);
    $('a[href]').each((i, el) => {
      const href = $(el).attr('href');
      if (href && !href.startsWith('#') && !href.startsWith('javascript:') && !href.startsWith('data:')) {
        try {
          const absolute = new URL(href, targetUrl).href;
          $(el).attr('href', `/proxy?url=${encodeURIComponent(absolute)}`);
        } catch (e) {}
      }
    });
    $('head').prepend(`<base href="${targetUrl}">`);
    res.set(response.headers);
    res.send($.html());
  } catch (error) { res.status(500).send('Proxy error: ' + error.message); }
});

// ========== Поиск групп ==========
app.get('/search_groups', (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  const ids = dbList('chats');
  const results = [];
  for (const id of ids) {
    const chat = dbGet('chats', id);
    if (chat && (chat.type === 'group' || chat.type === 'channel') && chat.name.toLowerCase().includes(q)) {
      results.push({ id, type: chat.type, name: chat.name, membersCount: chat.members.length });
    }
  }
  res.json(results);
});

// ========== Файлы ==========
app.get('/get_upload_token', (req, res) => {
  const token = crypto.randomBytes(16).toString('hex');
  uploadTokens[token] = { valid: true, created: Date.now() };
  res.json({ token });
});
app.post('/upload_file', upload.single('file'), (req, res) => {
  const token = req.headers['x-upload-token'];
  if (!token || !uploadTokens[token]?.valid) return res.status(403).json({ error: 'Invalid token' });
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'No file' });
  const fileUrl = `/files/${file.filename}`;
  res.json({ url: fileUrl, name: file.originalname, size: file.size, type: file.mimetype });
});
app.get('/files/:filename', (req, res) => {
  const filePath = path.join(uploadDir, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('File not found');
  res.sendFile(filePath);
});

// ========== Spotify ==========
app.post('/spotify/token', async (req, res) => {
  const { code, code_verifier, redirect_uri } = req.body;
  const client_id = process.env.SPOTIFY_CLIENT_ID;
  const client_secret = process.env.SPOTIFY_CLIENT_SECRET;
  if (!code || !code_verifier || !client_id || !client_secret) return res.status(400).json({ error: 'Missing params' });
  const params = new URLSearchParams({ grant_type:'authorization_code', code, redirect_uri, client_id, code_verifier });
  const response = await axios.post('https://accounts.spotify.com/api/token', params.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: 'Basic ' + Buffer.from(client_id + ':' + client_secret).toString('base64')
    }
  });
  res.json(response.data);
});
app.post('/spotify/save-token', async (req, res) => {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const users = dbList('skyid_users');
  let login;
  for (const l of users) { const u = dbGet('skyid_users', l); if (u && u.token === auth) { login = l; break; } }
  if (!login) return res.status(401).json({ error: 'Invalid user' });
  const { spotify_token, spotify_refresh, expires_at } = req.body;
  if (!spotify_token) return res.status(400).json({ error: 'Missing token' });
  const enc = encryptForStorage(JSON.stringify({ access_token: spotify_token, refresh_token: spotify_refresh || null, expires_at: expires_at || null }));
  dbPut('spotify_tokens', login, JSON.parse(enc));
  res.json({ ok: true });
});
app.get('/spotify/get-token', async (req, res) => {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const users = dbList('skyid_users');
  let login;
  for (const l of users) { const u = dbGet('skyid_users', l); if (u && u.token === auth) { login = l; break; } }
  if (!login) return res.status(401).json({ error: 'Invalid user' });
  const encObj = dbGet('spotify_tokens', login);
  if (!encObj) return res.json({ token: null });
  const data = JSON.parse(decryptFromStorage(JSON.stringify(encObj)));
  res.json({ access_token: data.access_token, refresh_token: data.refresh_token, expires_at: data.expires_at });
});

// ========== Соцсеть ==========
function verifyToken(req, res, next) {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const users = dbList('skyid_users');
  for (const login of users) {
    const user = dbGet('skyid_users', login);
    if (user && user.token === auth) { req.skyid = user.skyid; req.login = user.login; req.isAdmin = (user.login === ADMIN_LOGIN); return next(); }
  }
  res.status(401).json({ error: 'Invalid token' });
}
function adminRequired(req, res, next) { if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' }); next(); }
app.get('/posts', verifyToken, (req, res) => {
  const ids = dbList('social_posts');
  const posts = ids.map(id => dbGet('social_posts', id)).filter(Boolean).sort((a,b) => b.created - a.created).slice(0,50);
  res.json(posts);
});
app.post('/posts', verifyToken, (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  const post = { id: 'post_' + Date.now(), skyid: req.skyid, author: req.login, text, created: Date.now(), likes: [], dislikes: [], comments: [] };
  dbPut('social_posts', post.id, post);
  res.json(post);
});
app.delete('/posts/:id', verifyToken, (req, res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  if (post.skyid !== req.skyid && !req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  dbDelete('social_posts', req.params.id);
  res.json({ ok: true });
});
app.post('/posts/:id/like', verifyToken, (req, res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  post.dislikes = post.dislikes.filter(id => id !== req.skyid);
  if (!post.likes.includes(req.skyid)) post.likes.push(req.skyid); else post.likes = post.likes.filter(id => id !== req.skyid);
  dbPut('social_posts', req.params.id, post);
  res.json({ likes: post.likes.length, dislikes: post.dislikes.length });
});
app.post('/posts/:id/dislike', verifyToken, (req, res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  post.likes = post.likes.filter(id => id !== req.skyid);
  if (!post.dislikes.includes(req.skyid)) post.dislikes.push(req.skyid); else post.dislikes = post.dislikes.filter(id => id !== req.skyid);
  dbPut('social_posts', req.params.id, post);
  res.json({ likes: post.likes.length, dislikes: post.dislikes.length });
});
app.get('/posts/:id/comments', verifyToken, (req, res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  res.json(post.comments || []);
});
app.post('/posts/:id/comments', verifyToken, (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  const comment = { id: 'comment_' + Date.now(), skyid: req.skyid, author: req.login, text, created: Date.now(), likes: [], dislikes: [] };
  post.comments.push(comment);
  dbPut('social_posts', req.params.id, post);
  res.json(comment);
});
app.delete('/posts/:id/comments/:commentId', verifyToken, (req, res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  const comment = post.comments.find(c => c.id === req.params.commentId);
  if (!comment) return res.status(404).json({ error: 'Comment not found' });
  if (comment.skyid !== req.skyid && !req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  post.comments = post.comments.filter(c => c.id !== req.params.commentId);
  dbPut('social_posts', req.params.id, post);
  res.json({ ok: true });
});
app.post('/admin/ban', verifyToken, adminRequired, (req, res) => {
  const { skyid } = req.body;
  if (!skyid) return res.status(400).json({ error: 'skyid required' });
  dbPut('social_bans', skyid, { skyid, bannedAt: Date.now() });
  res.json({ ok: true });
});
app.post('/admin/unban', verifyToken, adminRequired, (req, res) => {
  const { skyid } = req.body;
  dbDelete('social_bans', skyid);
  res.json({ ok: true });
});

// ========== Поиск (SkySearch) – заглушка (можно добавить функции fetchDuckDuckGo и т.д.) ==========
app.post('/api/search', async (req, res) => {
  res.json({ data: await encryptClientResponse({ query: '', results: [] }) });
});

// ========== WebSocket (мессенджер) ==========
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const connections = {};
const chatListCache = new Map();

wss.on('connection', (ws) => {
  let currentUser = null;
  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }
    if (msg.type === 'auth') {
      const user = dbGet('chat_users', msg.login);
      if (!user) return ws.send(JSON.stringify({ type: 'error', message: 'User not found' }));
      currentUser = msg.login;
      connections[currentUser] = ws;
      user.status = 'online';
      dbPut('chat_users', msg.login, user);
      ws.send(JSON.stringify({ type: 'auth_ok', ...user, login: msg.login }));
      await sendChatList(currentUser);
      return;
    }
    if (!currentUser) return;
    try {
      switch (msg.type) {
        case 'get_chats': await sendChatList(currentUser); break;
        case 'get_messages': await handleGetMessages(ws, currentUser, msg.chatId); break;
        case 'send_message': await handleSendMessage(currentUser, msg.chatId, msg.text, null); break;
        case 'file_message': await handleSendMessage(currentUser, msg.chatId, msg.text, msg.file); break;
        case 'edit_message': await handleEditMessage(currentUser, msg.chatId, msg.messageId, msg.newText); break;
        case 'delete_message': await handleDeleteMessage(currentUser, msg.chatId, msg.messageId); break;
        case 'search_user': {
          const all = dbList('chat_users').filter(u => u !== currentUser && u.toLowerCase().includes((msg.query || '').toLowerCase()));
          ws.send(JSON.stringify({ type: 'user_search_result', users: all.map(u => ({ login: u })) }));
          break;
        }
        case 'create_private_chat': await createPrivateChat(currentUser, msg.target); break;
        case 'create_group': await createGroup(currentUser, msg.name); break;
        case 'create_channel': await createChannel(currentUser, msg.name); break;
        case 'update_profile': await updateProfile(currentUser, msg, ws); break;
        case 'join_group': await joinGroup(currentUser, msg.chatId); break;
        case 'leave_group': await leaveGroup(currentUser, msg.chatId); break;
        case 'delete_chat': await deleteChat(currentUser, msg.chatId); break;
        case 'block_chat': await blockChat(currentUser, msg.chatId); break;
        case 'unblock_chat': await unblockChat(currentUser, msg.chatId); break;
        case 'call_offer': case 'call_answer': case 'ice_candidate': case 'call_end':
          await forwardSignaling(msg, currentUser); break;
        default: ws.send(JSON.stringify({ type: 'error', message: 'Unknown type' }));
      }
    } catch (e) { ws.send(JSON.stringify({ type: 'error', message: 'Server error' })); }
  });
  ws.on('close', () => {
    if (currentUser) {
      delete connections[currentUser];
      const user = dbGet('chat_users', currentUser);
      if (user) { user.status = 'offline'; dbPut('chat_users', currentUser, user); }
    }
  });
});

async function sendChatList(user) {
  const cached = chatListCache.get(user);
  if (cached && (Date.now() - cached.timestamp) < 2000) {
    if (connections[user]) connections[user].send(JSON.stringify({ type: 'chat_list', chats: cached.chats }));
    return;
  }
  const ids = dbList('chats');
  const list = {};
  for (const id of ids) {
    const chat = dbGet('chats', id);
    if (!chat || chat.hidden?.includes(user)) continue;
    if (!chat.members.includes(user)) continue;
    let name = chat.name;
    if (chat.type === 'private') name = chat.members.find(m => m !== user) || chat.name;
    list[id] = { id, type: chat.type, name, lastMsg: chat.messages?.slice(-1)[0]?.text?.slice(0,30) || '', blocked: chat.blocked?.includes(user) || false };
  }
  chatListCache.set(user, { chats: list, timestamp: Date.now() });
  if (connections[user]) connections[user].send(JSON.stringify({ type: 'chat_list', chats: list }));
}
async function handleGetMessages(ws, user, chatId) {
  const chat = dbGet('chats', chatId);
  if (!chat || !chat.members.includes(user)) return ws.send(JSON.stringify({ type: 'messages', messages: [] }));
  ws.send(JSON.stringify({ type: 'messages', messages: chat.messages || [] }));
}
async function handleSendMessage(user, chatId, text, file) {
  const chat = dbGet('chats', chatId);
  if (!chat || !chat.members.includes(user)) return;
  const message = { id: 'msg_' + Date.now(), from: user, text: text || '', time: Date.now() };
  if (file) message.file = { name: file.name, type: file.type, data: file.url || file.data, size: file.size };
  chat.messages = chat.messages || [];
  chat.messages.push(message);
  dbPut('chats', chatId, chat);
  for (const m of chat.members) {
    if (m !== user && connections[m] && !chat.blocked?.includes(m)) {
      connections[m].send(JSON.stringify({ type: 'message', chatId, ...message }));
    }
  }
}
async function handleEditMessage(user, chatId, messageId, newText) {
  const chat = dbGet('chats', chatId);
  if (!chat || !chat.members.includes(user)) return;
  const msg = chat.messages.find(m => m.id === messageId);
  if (!msg || msg.from !== user) return;
  msg.text = newText; msg.edited = true;
  dbPut('chats', chatId, chat);
  chat.members.forEach(m => {
    if (connections[m] && !chat.blocked?.includes(m)) {
      connections[m].send(JSON.stringify({ type: 'message_edited', chatId, messageId, newText }));
    }
  });
}
async function handleDeleteMessage(user, chatId, messageId) {
  const chat = dbGet('chats', chatId);
  if (!chat || !chat.members.includes(user)) return;
  const msg = chat.messages.find(m => m.id === messageId);
  if (!msg || (msg.from !== user && chat.members[0] !== user)) return;
  chat.messages = chat.messages.filter(m => m.id !== messageId);
  dbPut('chats', chatId, chat);
  chat.members.forEach(m => {
    if (connections[m] && !chat.blocked?.includes(m)) {
      connections[m].send(JSON.stringify({ type: 'message_deleted', chatId, messageId }));
    }
  });
}
async function createPrivateChat(u1, u2) {
  const user = dbGet('chat_users', u2);
  if (!user) return;
  const id = [u1, u2].sort().join('_');
  if (!dbGet('chats', id)) dbPut('chats', id, { type: 'private', members: [u1, u2], messages: [], created: Date.now() });
  await sendChatList(u1); await sendChatList(u2);
  if (connections[u1]) connections[u1].send(JSON.stringify({ type: 'chat_created', chatId: id }));
}
async function createGroup(user, name) {
  const id = 'group_' + Date.now();
  dbPut('chats', id, { type: 'group', name, members: [user], messages: [], created: Date.now() });
  await sendChatList(user);
}
async function createChannel(user, name) {
  const id = 'channel_' + Date.now();
  dbPut('chats', id, { type: 'channel', name, members: [user], messages: [], created: Date.now() });
  await sendChatList(user);
}
async function joinGroup(user, chatId) {
  const chat = dbGet('chats', chatId);
  if (!chat || (chat.type !== 'group' && chat.type !== 'channel')) return;
  if (!chat.members.includes(user)) { chat.members.push(user); dbPut('chats', chatId, chat); }
  await sendChatList(user);
}
async function leaveGroup(user, chatId) {
  const chat = dbGet('chats', chatId);
  if (!chat || (chat.type !== 'group' && chat.type !== 'channel')) return;
  chat.members = chat.members.filter(m => m !== user);
  dbPut('chats', chatId, chat);
  await sendChatList(user);
}
async function deleteChat(user, chatId) {
  const chat = dbGet('chats', chatId);
  if (!chat) return;
  if (chat.type === 'private') {
    if (!chat.hidden) chat.hidden = [];
    if (!chat.hidden.includes(user)) chat.hidden.push(user);
    dbPut('chats', chatId, chat);
  } else if ((chat.type === 'group' || chat.type === 'channel') && chat.members[0] === user) {
    dbDelete('chats', chatId);
  }
  await sendChatList(user);
}
async function blockChat(user, chatId) {
  const chat = dbGet('chats', chatId);
  if (!chat) return;
  if (!chat.blocked) chat.blocked = [];
  if (!chat.blocked.includes(user)) chat.blocked.push(user);
  dbPut('chats', chatId, chat);
  await sendChatList(user);
}
async function unblockChat(user, chatId) {
  const chat = dbGet('chats', chatId);
  if (!chat) return;
  if (chat.blocked) chat.blocked = chat.blocked.filter(m => m !== user);
  dbPut('chats', chatId, chat);
  await sendChatList(user);
}
async function updateProfile(user, data, ws) {
  const profile = dbGet('chat_users', user);
  if (!profile) return;
  if (data.name) profile.name = data.name;
  if (data.status) profile.status = data.status;
  if (data.avatar) profile.avatar = data.avatar;
  dbPut('chat_users', user, profile);
  ws.send(JSON.stringify({ type: 'profile_updated', profile }));
}
async function forwardSignaling(msg, from) {
  const chat = dbGet('chats', msg.chatId);
  if (!chat) return;
  const other = chat.members.find(m => m !== from);
  if (other && connections[other]) {
    connections[other].send(JSON.stringify({ ...msg, from }));
  }
}

server.listen(PORT, () => console.log(`SkyCitadel running on port ${PORT}`));
