const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const multer = require('multer');
const cheerio = require('cheerio');
const NodeCache = require('node-cache');
const jwt = require('jsonwebtoken');

const app = express();

// ====== Таймауты и логирование ======
app.use((req, res, next) => {
  req.setTimeout(120000);
  res.setTimeout(120000);
  next();
});

app.use((req, res, next) => {
  const start = Date.now();
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} started`);
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} finished in ${duration}ms`);
  });
  next();
});

// ====== СТАТИКА ======
app.use(express.static('public'));

// ====== CORS ======
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-upload-token']
}));
app.options('*', cors());

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const ADMIN_LOGIN = process.env.ADMIN_LOGIN || 'SkyMonder';
const CLIENT_SECRET = "BLx5Vp7U1c8dR2mQkG4fJ6yA9tC3bF0zH7iL2nM5oP8=";
const CLIENT_KEY = Buffer.from(CLIENT_SECRET, 'base64');
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
let STORAGE_KEY = Buffer.from(process.env.STORAGE_KEY_HEX || crypto.randomBytes(32).toString('hex'), 'hex');

// ---------- Асинхронная файловая БД ----------
const DATA_DIR = path.join(__dirname, 'data');
(async () => { try { await fs.mkdir(DATA_DIR, { recursive: true }); } catch (e) {} })();

const listCache = new Map();

async function ensureBucketDir(bucket) {
  const dir = path.join(DATA_DIR, bucket);
  try { await fs.mkdir(dir, { recursive: true }); } catch (e) {}
  return dir;
}

async function dbPut(bucket, key, data) {
  const dir = await ensureBucketDir(bucket);
  await fs.writeFile(path.join(dir, key + '.json'), JSON.stringify(data, null, 2));
  listCache.delete(bucket);
}

async function dbGet(bucket, key) {
  try {
    const content = await fs.readFile(path.join(DATA_DIR, bucket, key + '.json'), 'utf-8');
    return JSON.parse(content);
  } catch (e) { return null; }
}

async function dbList(bucket) {
  const cached = listCache.get(bucket);
  if (cached && (Date.now() - cached.timestamp < 2000)) return cached.keys;
  const dir = path.join(DATA_DIR, bucket);
  try {
    await fs.mkdir(dir, { recursive: true });
    const files = await fs.readdir(dir);
    const keys = files.filter(f => f.endsWith('.json')).map(f => f.slice(0, -5));
    listCache.set(bucket, { keys, timestamp: Date.now() });
    return keys;
  } catch (e) { return []; }
}

async function dbDelete(bucket, key) {
  try { await fs.unlink(path.join(DATA_DIR, bucket, key + '.json')); } catch (e) {}
  listCache.delete(bucket);
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

// ---------- JWT Helpers ----------
function generateJWT(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function verifyJWT(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

// ---------- Загрузка файлов ----------
const uploadDir = path.join(__dirname, 'uploads');
if (!fsSync.existsSync(uploadDir)) fsSync.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + '_' + Math.random().toString(36).slice(2,8) + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 10*1024*1024 } });
const uploadTokens = {};

// ========== КЕШИРОВАНИЕ ==========
const userCache = new NodeCache({ stdTTL: 600, checkperiod: 120 });
const tokenCache = new NodeCache({ stdTTL: 3600, checkperiod: 300 });
const announcementCache = { data: null, time: 0 };

async function getCachedUser(login) {
  let user = userCache.get(login);
  if (!user) {
    user = await dbGet('skyid_users', login);
    if (user) userCache.set(login, user);
  }
  return user;
}

let skyidIndex = null;
async function buildSkyidIndex() {
  if (skyidIndex) return skyidIndex;
  skyidIndex = new Map();
  const logins = await dbList('skyid_users');
  for (const login of logins) {
    const user = await getCachedUser(login);
    if (user) skyidIndex.set(user.skyid, login);
  }
  return skyidIndex;
}
async function getUserBySkyid(skyid) {
  const index = await buildSkyidIndex();
  const login = index.get(skyid);
  if (login) return await getCachedUser(login);
  return null;
}

async function saveToken(token, login, expiresInSeconds = 7*24*3600) {
  const expires = Date.now() + expiresInSeconds * 1000;
  await dbPut('tokens', token, { login, expires });
  tokenCache.set(token, { login, expires });
}

async function getTokenData(token) {
  let data = tokenCache.get(token);
  if (!data) {
    data = await dbGet('tokens', token);
    if (data) tokenCache.set(token, data);
  }
  return data;
}

async function deleteToken(token) {
  await dbDelete('tokens', token);
  tokenCache.del(token);
}

// ========== Health ==========
app.get('/healthix', (req, res) => res.json({ status: 'ok' }));

// ========== SkyCounter ==========
const SITES = ['skycitadel.onrender.com', 'skycitadel.cc.cd'];
app.get('/checkvizit', async (req, res) => {
  const site = req.query.site;
  if (!site) return res.status(400).json({ error: 'Missing site' });
  if (!SITES.includes(site)) return res.status(403).json({ error: 'Site not allowed' });
  const today = new Date().toISOString().split('T')[0];
  const visits = await dbGet('visits', today) || [];
  if (!visits.includes(site)) { visits.push(site); await dbPut('visits', today, visits); return res.json({ status: 'ok', site, date: today }); }
  res.json({ status: 'already_exists', site, date: today });
});

// ========== Аутентификация (только JWT) ==========
app.post('/register', async (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'No data' });
  try {
    const payload = await decryptClientPayload(data);
    const { login, password } = payload;
    if (!login || !password) return res.status(400).json({ error: 'Login and password required' });
    if (await getCachedUser(login)) return res.status(409).json({ error: 'User exists' });
    const salt = crypto.randomBytes(16).toString('base64');
    const hash = await new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, 10000, 64, 'sha512', (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey.toString('hex'));
      });
    });
    const skyid = 'sid_' + crypto.randomBytes(8).toString('hex');
    const token = crypto.randomBytes(32).toString('hex');
    const jwtToken = generateJWT({ skyid, login });
    await dbPut('skyid_users', login, { skyid, login, salt, hash, token });
    userCache.set(login, { skyid, login, salt, hash, token });
    await saveToken(token, login, 7*24*3600);
    if (skyidIndex) skyidIndex.set(skyid, login);
    if (!(await dbGet('chat_users', login))) {
      await dbPut('chat_users', login, { salt, name: login, avatar: '', status: 'online' });
    }
    const enc = await encryptClientResponse({ skyid, token, jwt: jwtToken });
    res.json({ data: enc });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/login', async (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'No data' });
  try {
    const payload = await decryptClientPayload(data);
    const { login, password } = payload;
    if (!login || !password) return res.status(400).json({ error: 'Login and password required' });
    const user = await getCachedUser(login);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const hash = await new Promise((resolve, reject) => {
      crypto.pbkdf2(password, user.salt, 10000, 64, 'sha512', (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey.toString('hex'));
      });
    });
    if (hash !== user.hash) return res.status(401).json({ error: 'Invalid credentials' });
    const newToken = crypto.randomBytes(32).toString('hex');
    const jwtToken = generateJWT({ skyid: user.skyid, login });
    user.token = newToken;
    await dbPut('skyid_users', login, user);
    userCache.set(login, user);
    await saveToken(newToken, login, 7*24*3600);
    const enc = await encryptClientResponse({ skyid: user.skyid, token: newToken, jwt: jwtToken });
    res.json({ data: enc });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/verify', async (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.replace('Bearer ', '') || req.body.token;
  if (!token) return res.status(400).json({ error: 'Token required' });

  const decoded = verifyJWT(token);
  if (decoded) {
    const user = await getUserBySkyid(decoded.skyid);
    if (user) {
      return res.json({ skyid: decoded.skyid, login: decoded.login });
    }
  }

  const tokenData = await getTokenData(token);
  if (!tokenData) return res.status(401).json({ error: 'Invalid token' });
  if (tokenData.expires < Date.now()) {
    await deleteToken(token);
    return res.status(401).json({ error: 'Token expired' });
  }
  const user = await getCachedUser(tokenData.login);
  if (!user) return res.status(401).json({ error: 'User not found' });
  res.json({ skyid: user.skyid, login: user.login });
});

// ========== Чат-регистрация ==========
app.post('/chat/register', async (req, res) => {
  const { login, salt } = req.body;
  if (!login || !salt) return res.status(400).json({ error: 'login and salt required' });
  if (await dbGet('chat_users', login)) return res.status(409).json({ error: 'User exists' });
  await dbPut('chat_users', login, { salt, name: login, avatar: '', status: 'online' });
  res.json({ ok: true });
});
app.get('/chat/login_salt', async (req, res) => {
  const login = req.query.login;
  if (!login) return res.status(400).json({ error: 'login required' });
  const user = await dbGet('chat_users', login);
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
  if (Date.now() - announcementCache.time < 60000 && announcementCache.data) {
    return res.json({ data: await encryptClientResponse(announcementCache.data) });
  }
  const keys = await dbList('announcements');
  const list = [];
  for (const k of keys) {
    const item = await dbGet('announcements', k);
    if (item) list.push(item);
  }
  list.sort((a,b) => b.created - a.created);
  announcementCache.data = list;
  announcementCache.time = Date.now();
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
  let isAdmin = false;
  const decoded = verifyJWT(auth);
  if (decoded && decoded.login === ADMIN_LOGIN) {
    isAdmin = true;
  } else {
    const users = await dbList('skyid_users');
    for (const login of users) {
      const u = await getCachedUser(login);
      if (u && u.token === auth && u.login === ADMIN_LOGIN) { isAdmin = true; break; }
    }
  }
  if (!isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const ann = { id: 'ann_' + Date.now(), text, created: Date.now() };
  await dbPut('announcements', ann.id, ann);
  announcementCache.data = null;
  announcementCache.time = 0;
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
app.get('/search_groups', async (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  const ids = await dbList('chats');
  const results = [];
  for (const id of ids) {
    const chat = await dbGet('chats', id);
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
  if (!fsSync.existsSync(filePath)) return res.status(404).send('File not found');
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
  const users = await dbList('skyid_users');
  let login = null;
  for (const l of users) { const u = await getCachedUser(l); if (u && u.token === auth) { login = l; break; } }
  if (!login) return res.status(401).json({ error: 'Invalid user' });
  const { spotify_token, spotify_refresh, expires_at } = req.body;
  if (!spotify_token) return res.status(400).json({ error: 'Missing token' });
  const enc = encryptForStorage(JSON.stringify({ access_token: spotify_token, refresh_token: spotify_refresh || null, expires_at: expires_at || null }));
  await dbPut('spotify_tokens', login, JSON.parse(enc));
  res.json({ ok: true });
});
app.get('/spotify/get-token', async (req, res) => {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const users = await dbList('skyid_users');
  let login = null;
  for (const l of users) { const u = await getCachedUser(l); if (u && u.token === auth) { login = l; break; } }
  if (!login) return res.status(401).json({ error: 'Invalid user' });
  const encObj = await dbGet('spotify_tokens', login);
  if (!encObj) return res.json({ token: null });
  const data = JSON.parse(decryptFromStorage(JSON.stringify(encObj)));
  res.json({ access_token: data.access_token, refresh_token: data.refresh_token, expires_at: data.expires_at });
});

// ========== Соцсеть ==========
async function verifyToken(req, res, next) {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });

  const decoded = verifyJWT(auth);
  if (decoded) {
    const user = await getUserBySkyid(decoded.skyid);
    if (user) {
      req.skyid = user.skyid;
      req.login = user.login;
      req.isAdmin = (user.login === ADMIN_LOGIN);
      return next();
    }
  }

  const tokenData = await getTokenData(auth);
  if (tokenData && tokenData.expires > Date.now()) {
    const user = await getCachedUser(tokenData.login);
    if (user) {
      req.skyid = user.skyid;
      req.login = user.login;
      req.isAdmin = (user.login === ADMIN_LOGIN);
      return next();
    }
  }

  const users = await dbList('skyid_users');
  for (const login of users) {
    const user = await getCachedUser(login);
    if (user && user.token === auth) {
      req.skyid = user.skyid;
      req.login = user.login;
      req.isAdmin = (user.login === ADMIN_LOGIN);
      return next();
    }
  }
  res.status(401).json({ error: 'Invalid token' });
}
function adminRequired(req, res, next) { if (!req.isAdmin) return res.status(403).json({ error: 'Forbidden' }); next(); }

app.get('/posts', verifyToken, async (req, res) => {
  const ids = await dbList('social_posts');
  const posts = [];
  for (const id of ids) {
    const post = await dbGet('social_posts', id);
    if (post) posts.push(post);
  }
  posts.sort((a,b) => b.created - a.created);
  res.json(posts.slice(0,50));
});
app.post('/posts', verifyToken, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  const post = { id: 'post_' + Date.now(), skyid: req.skyid, author: req.login, text, created: Date.now(), likes: [], dislikes: [], comments: [] };
  await dbPut('social_posts', post.id, post);
  res.json(post);
});
app.delete('/posts/:id', verifyToken, async (req, res) => {
  const post = await dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  if (post.skyid !== req.skyid && !req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  await dbDelete('social_posts', req.params.id);
  res.json({ ok: true });
});
app.post('/posts/:id/like', verifyToken, async (req, res) => {
  const post = await dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  post.dislikes = post.dislikes.filter(id => id !== req.skyid);
  if (!post.likes.includes(req.skyid)) post.likes.push(req.skyid); else post.likes = post.likes.filter(id => id !== req.skyid);
  await dbPut('social_posts', req.params.id, post);
  res.json({ likes: post.likes.length, dislikes: post.dislikes.length });
});
app.post('/posts/:id/dislike', verifyToken, async (req, res) => {
  const post = await dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  post.likes = post.likes.filter(id => id !== req.skyid);
  if (!post.dislikes.includes(req.skyid)) post.dislikes.push(req.skyid); else post.dislikes = post.dislikes.filter(id => id !== req.skyid);
  await dbPut('social_posts', req.params.id, post);
  res.json({ likes: post.likes.length, dislikes: post.dislikes.length });
});
app.get('/posts/:id/comments', verifyToken, async (req, res) => {
  const post = await dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  res.json(post.comments || []);
});
app.post('/posts/:id/comments', verifyToken, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  const post = await dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  const comment = { id: 'comment_' + Date.now(), skyid: req.skyid, author: req.login, text, created: Date.now(), likes: [], dislikes: [] };
  post.comments.push(comment);
  await dbPut('social_posts', req.params.id, post);
  res.json(comment);
});
app.delete('/posts/:id/comments/:commentId', verifyToken, async (req, res) => {
  const post = await dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error: 'Not found' });
  const comment = post.comments.find(c => c.id === req.params.commentId);
  if (!comment) return res.status(404).json({ error: 'Comment not found' });
  if (comment.skyid !== req.skyid && !req.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  post.comments = post.comments.filter(c => c.id !== req.params.commentId);
  await dbPut('social_posts', req.params.id, post);
  res.json({ ok: true });
});
app.post('/admin/ban', verifyToken, adminRequired, async (req, res) => {
  const { skyid } = req.body;
  if (!skyid) return res.status(400).json({ error: 'skyid required' });
  await dbPut('social_bans', skyid, { skyid, bannedAt: Date.now() });
  res.json({ ok: true });
});
app.post('/admin/unban', verifyToken, adminRequired, async (req, res) => {
  const { skyid } = req.body;
  await dbDelete('social_bans', skyid);
  res.json({ ok: true });
});

// ========== Поиск (заглушка) ==========
app.post('/api/search', async (req, res) => {
  res.json({ data: await encryptClientResponse({ query: '', results: [] }) });
});

// ========== АДМИН-ПАНЕЛЬ (эндпоинты) ==========

// Проверка, что пользователь – администратор
async function isAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
  const token = authHeader.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const decoded = verifyJWT(token);
  if (!decoded || !decoded.login) return res.status(401).json({ error: 'Invalid token' });

  const user = await getCachedUser(decoded.login);
  if (!user || user.login !== ADMIN_LOGIN) {
    return res.status(403).json({ error: 'Forbidden: admin only' });
  }
  req.user = user;
  next();
}

// Список всех пользователей (только админ)
app.get('/admin/users', isAdmin, async (req, res) => {
  try {
    const logins = await dbList('skyid_users');
    const users = [];
    for (const login of logins) {
      const user = await getCachedUser(login);
      if (user) {
        users.push({
          login: user.login,
          skyid: user.skyid,
          name: user.name || user.login,
          avatar: user.avatar || '',
          isAdmin: user.login === ADMIN_LOGIN
        });
      }
    }
    res.json(users);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Статистика
app.get('/admin/stats', isAdmin, async (req, res) => {
  try {
    const users = await dbList('skyid_users');
    const videos = await dbList('videos') || [];
    const announcements = await dbList('announcements');
    res.json({
      users: users.length,
      videos: videos.length,
      announcements: announcements.length
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Удаление пользователя (только админ)
app.delete('/admin/user/:login', isAdmin, async (req, res) => {
  const login = req.params.login;
  if (login === ADMIN_LOGIN) {
    return res.status(403).json({ error: 'Cannot delete admin' });
  }
  try {
    const user = await getCachedUser(login);
    if (!user) return res.status(404).json({ error: 'User not found' });
    await dbDelete('skyid_users', login);
    await dbDelete('chat_users', login);
    const tokens = await dbList('tokens');
    for (const tok of tokens) {
      const data = await dbGet('tokens', tok);
      if (data && data.login === login) {
        await dbDelete('tokens', tok);
      }
    }
    userCache.del(login);
    if (skyidIndex) skyidIndex.delete(user.skyid);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ========== WebSocket (мессенджер) ==========
const server = http.createServer(app);
server.timeout = 120000;

const wss = new WebSocket.Server({ server });
const connections = {};
const chatListCache = new Map();

wss.on('connection', (ws, req) => {
  let currentUser = null;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  // Проверка бана (асинхронная)
  (async () => {
    const banned = await dbGet('banned_ips', ip);
    if (banned) {
      ws.send(JSON.stringify({ type: 'error', message: 'Ваш IP заблокирован за нарушения.' }));
      ws.close();
      return;
    }
  })();

  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch (e) { return; }
    if (msg.type === 'auth') {
      const user = await dbGet('chat_users', msg.login);
      if (!user) return ws.send(JSON.stringify({ type: 'error', message: 'User not found' }));
      currentUser = msg.login;
      connections[currentUser] = ws;
      user.status = 'online';
      await dbPut('chat_users', msg.login, user);
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
          const all = (await dbList('chat_users')).filter(u => u !== currentUser && u.toLowerCase().includes((msg.query || '').toLowerCase()));
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
      (async () => {
        const user = await dbGet('chat_users', currentUser);
        if (user) { user.status = 'offline'; await dbPut('chat_users', currentUser, user); }
      })();
    }
  });
});

async function sendChatList(user) {
  const cached = chatListCache.get(user);
  if (cached && (Date.now() - cached.timestamp) < 2000) {
    if (connections[user]) connections[user].send(JSON.stringify({ type: 'chat_list', chats: cached.chats }));
    return;
  }
  const ids = await dbList('chats');
  const list = {};
  for (const id of ids) {
    const chat = await dbGet('chats', id);
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
  const chat = await dbGet('chats', chatId);
  if (!chat || !chat.members.includes(user)) return ws.send(JSON.stringify({ type: 'messages', messages: [] }));
  ws.send(JSON.stringify({ type: 'messages', messages: chat.messages || [] }));
}
async function handleSendMessage(user, chatId, text, file) {
  const chat = await dbGet('chats', chatId);
  if (!chat || !chat.members.includes(user)) return;
  const message = { id: 'msg_' + Date.now(), from: user, text: text || '', time: Date.now() };
  if (file) message.file = { name: file.name, type: file.type, data: file.url || file.data, size: file.size };
  chat.messages = chat.messages || [];
  chat.messages.push(message);
  await dbPut('chats', chatId, chat);
  for (const m of chat.members) {
    if (m !== user && connections[m] && !chat.blocked?.includes(m)) {
      connections[m].send(JSON.stringify({ type: 'message', chatId, ...message }));
    }
  }
}
async function handleEditMessage(user, chatId, messageId, newText) {
  const chat = await dbGet('chats', chatId);
  if (!chat || !chat.members.includes(user)) return;
  const msg = chat.messages.find(m => m.id === messageId);
  if (!msg || msg.from !== user) return;
  msg.text = newText; msg.edited = true;
  await dbPut('chats', chatId, chat);
  chat.members.forEach(m => {
    if (connections[m] && !chat.blocked?.includes(m)) {
      connections[m].send(JSON.stringify({ type: 'message_edited', chatId, messageId, newText }));
    }
  });
}
async function handleDeleteMessage(user, chatId, messageId) {
  const chat = await dbGet('chats', chatId);
  if (!chat || !chat.members.includes(user)) return;
  const msg = chat.messages.find(m => m.id === messageId);
  if (!msg || (msg.from !== user && chat.members[0] !== user)) return;
  chat.messages = chat.messages.filter(m => m.id !== messageId);
  await dbPut('chats', chatId, chat);
  chat.members.forEach(m => {
    if (connections[m] && !chat.blocked?.includes(m)) {
      connections[m].send(JSON.stringify({ type: 'message_deleted', chatId, messageId }));
    }
  });
}
async function createPrivateChat(u1, u2) {
  const user = await dbGet('chat_users', u2);
  if (!user) return;
  const id = [u1, u2].sort().join('_');
  if (!(await dbGet('chats', id))) await dbPut('chats', id, { type: 'private', members: [u1, u2], messages: [], created: Date.now() });
  await sendChatList(u1); await sendChatList(u2);
  if (connections[u1]) connections[u1].send(JSON.stringify({ type: 'chat_created', chatId: id }));
}
async function createGroup(user, name) {
  const id = 'group_' + Date.now();
  await dbPut('chats', id, { type: 'group', name, members: [user], messages: [], created: Date.now() });
  await sendChatList(user);
}
async function createChannel(user, name) {
  const id = 'channel_' + Date.now();
  await dbPut('chats', id, { type: 'channel', name, members: [user], messages: [], created: Date.now() });
  await sendChatList(user);
}
async function joinGroup(user, chatId) {
  const chat = await dbGet('chats', chatId);
  if (!chat || (chat.type !== 'group' && chat.type !== 'channel')) return;
  if (!chat.members.includes(user)) { chat.members.push(user); await dbPut('chats', chatId, chat); }
  await sendChatList(user);
}
async function leaveGroup(user, chatId) {
  const chat = await dbGet('chats', chatId);
  if (!chat || (chat.type !== 'group' && chat.type !== 'channel')) return;
  chat.members = chat.members.filter(m => m !== user);
  await dbPut('chats', chatId, chat);
  await sendChatList(user);
}
async function deleteChat(user, chatId) {
  const chat = await dbGet('chats', chatId);
  if (!chat) return;
  if (chat.type === 'private') {
    if (!chat.hidden) chat.hidden = [];
    if (!chat.hidden.includes(user)) chat.hidden.push(user);
    await dbPut('chats', chatId, chat);
  } else if ((chat.type === 'group' || chat.type === 'channel') && chat.members[0] === user) {
    await dbDelete('chats', chatId);
  }
  await sendChatList(user);
}
async function blockChat(user, chatId) {
  const chat = await dbGet('chats', chatId);
  if (!chat) return;
  if (!chat.blocked) chat.blocked = [];
  if (!chat.blocked.includes(user)) chat.blocked.push(user);
  await dbPut('chats', chatId, chat);
  await sendChatList(user);
}
async function unblockChat(user, chatId) {
  const chat = await dbGet('chats', chatId);
  if (!chat) return;
  if (chat.blocked) chat.blocked = chat.blocked.filter(m => m !== user);
  await dbPut('chats', chatId, chat);
  await sendChatList(user);
}
async function updateProfile(user, data, ws) {
  const profile = await dbGet('chat_users', user);
  if (!profile) return;
  if (data.name) profile.name = data.name;
  if (data.status) profile.status = data.status;
  if (data.avatar) profile.avatar = data.avatar;
  await dbPut('chat_users', user, profile);
  ws.send(JSON.stringify({ type: 'profile_updated', profile }));
}
async function forwardSignaling(msg, from) {
  const chat = await dbGet('chats', msg.chatId);
  if (!chat) return;
  const other = chat.members.find(m => m !== from);
  if (other && connections[other]) {
    connections[other].send(JSON.stringify({ ...msg, from }));
  }
}

// ====== ИНИЦИАЛИЗАЦИЯ АДМИНИСТРАТОРА ======
(async function initAdmin() {
  const adminLogin = process.env.ADMIN_LOGIN || 'SkyMonder';
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (!adminPassword) {
    console.warn('⚠️ ADMIN_PASSWORD не задан в переменных окружения. Администратор не будет создан автоматически.');
    return;
  }
  const existing = await getCachedUser(adminLogin);
  if (existing) {
    console.log(`✅ Администратор ${adminLogin} уже существует.`);
    return;
  }
  const salt = crypto.randomBytes(16).toString('base64');
  const hash = await new Promise((resolve, reject) => {
    crypto.pbkdf2(adminPassword, salt, 10000, 64, 'sha512', (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey.toString('hex'));
    });
  });
  const skyid = 'sid_' + crypto.randomBytes(8).toString('hex');
  const token = crypto.randomBytes(32).toString('hex');
  await dbPut('skyid_users', adminLogin, { skyid, login: adminLogin, salt, hash, token });
  userCache.set(adminLogin, { skyid, login: adminLogin, salt, hash, token });
  if (skyidIndex) skyidIndex.set(skyid, adminLogin);
  console.log(`🔑 Администратор ${adminLogin} создан! Сохраните пароль: ${adminPassword}`);
})();

// ====== ПОИСК (OpenSERP) ======
app.get('/api/search', async (req, res) => {
  const query = req.query.q;
  const count = parseInt(req.query.count) || 10;
  const offset = parseInt(req.query.offset) || 0;
  const engine = req.query.engine || 'duckduckgo';
  if (!query) {
    return res.status(400).json({ error: 'Missing query parameter "q"' });
  }
  const OPENSERP_URL = process.env.OPENSERP_URL || 'https://skymutant.cc.cd/openserp';
  try {
    const openserpUrl = `${OPENSERP_URL}/${engine}/search?text=${encodeURIComponent(query)}&limit=${count}&start=${offset}`;
    console.log('Search request:', openserpUrl);
    const response = await fetch(openserpUrl);
    if (!response.ok) {
      const errorText = await response.text();
      console.error('OpenSERP error:', response.status, errorText);
      return res.status(response.status).json({ error: 'Search engine error' });
    }
    const data = await response.json();
    const results = data.results?.map(item => ({
      title: item.title || '',
      url: item.url || '',
      description: item.snippet || item.description || '',
      icon: item.favicon || `https://www.google.com/s2/favicons?domain=${item.domain || new URL(item.url).hostname}&sz=32`
    })) || [];
    res.json({
      query,
      results,
      total: results.length,
      nextOffset: offset + results.length
    });
  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ====== МОДЕРАЦИЯ И БАНЫ ======

// Получить IP клиента
app.get('/get_ip', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';
  res.json({ ip });
});

// Репорт о нарушении
const MAX_VIOLATIONS = 3;
app.post('/report_violation', async (req, res) => {
  const { login, ip, text, score } = req.body;
  if (!login || !ip || !text) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  let violations = await dbGet('violations', ip);
  if (!violations) violations = { count: 0, reports: [] };
  violations.count += 1;
  violations.reports.push({
    login,
    text,
    score,
    timestamp: Date.now(),
    id: Date.now() + '_' + Math.random().toString(36).slice(2,6)
  });
  await dbPut('violations', ip, violations);
  if (violations.count >= MAX_VIOLATIONS) {
    await dbPut('banned_ips', ip, { bannedAt: Date.now(), reason: 'Exceeded violation limit' });
  }
  res.json({ ok: true });
});

// Админ-панель: список нарушений
app.get('/admin/violations', isAdmin, async (req, res) => {
  const ips = await dbList('violations');
  const allReports = [];
  for (const ip of ips) {
    const data = await dbGet('violations', ip);
    if (data && data.reports) {
      data.reports.forEach(r => {
        allReports.push({ ip, ...r });
      });
    }
  }
  allReports.sort((a,b) => b.timestamp - a.timestamp);
  res.json(allReports);
});

// Админ-панель: разбан IP
app.post('/admin/unban', isAdmin, async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  await dbDelete('banned_ips', ip);
  res.json({ ok: true });
});

server.listen(PORT, () => console.log(`SkyMutant running on port ${PORT}`));
