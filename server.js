const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const cheerio = require('cheerio');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization','x-upload-token'] }));
app.options('*', cors());
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000;
const ADMIN_LOGIN = process.env.ADMIN_LOGIN || 'SkyMonder';
const CLIENT_SECRET = "BLx5Vp7U1c8dR2mQkG4fJ6yA9tC3bF0zH7iL2nM5oP8=";
const CLIENT_KEY = Buffer.from(CLIENT_SECRET, 'base64');

// ---------- Файловая база данных (замена отдельному сервису) ----------
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
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5));
}

function dbDelete(bucket, key) {
  const file = path.join(DATA_DIR, bucket, key + '.json');
  if (fs.existsSync(file)) fs.unlinkSync(file);
}

// ---------- Шифрование ----------
let STORAGE_KEY = Buffer.from(process.env.STORAGE_KEY_HEX || crypto.randomBytes(32).toString('hex'), 'hex');

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

// ---------- Клиентское шифрование (для погоды, объявлений, поиска, SkyID) ----------
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
app.get('/healthix', (req,res) => res.json({ status:'ok' }));

// ========== SkyID ==========
app.post('/register', async (req,res) => {
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ error:'No data' });
    const payload = await decryptClientPayload(data);
    const { login, password } = payload;
    if (!login || !password) return res.status(400).json({ error:'login/password required' });

    if (dbGet('skyid_users', login)) return res.status(409).json({ error:'User exists' });
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    const skyid = 'sky_' + crypto.randomBytes(4).toString('hex');
    const token = crypto.randomBytes(32).toString('hex');

    dbPut('skyid_users', login, { skyid, salt, hash, token, name: login, avatar: '', status: 'online' });
    const answer = { skyid, token };
    const encResponse = await encryptClientResponse(answer);
    res.json({ data: encResponse });
  } catch(e) { res.status(500).json({ error:'Internal error' }); }
});

app.post('/login', async (req,res) => {
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ error:'No data' });
    const payload = await decryptClientPayload(data);
    const { login, password } = payload;
    if (!login || !password) return res.status(400).json({ error:'login/password required' });

    const user = dbGet('skyid_users', login);
    if (!user) return res.status(404).json({ error:'User not found' });
    const hash = crypto.pbkdf2Sync(password, user.salt, 100000, 64, 'sha512').toString('hex');
    if (hash !== user.hash) return res.status(401).json({ error:'Invalid password' });

    const token = crypto.randomBytes(32).toString('hex');
    user.token = token;
    dbPut('skyid_users', login, user);
    const answer = { skyid: user.skyid, token };
    const encResponse = await encryptClientResponse(answer);
    res.json({ data: encResponse });
  } catch(e) { res.status(500).json({ error:'Internal error' }); }
});

app.get('/me', (req,res) => {
  const auth = req.headers.authorization?.replace('Bearer ','');
  if (!auth) return res.status(401).json({ error:'Unauthorized' });
  const users = dbList('skyid_users');
  for (const login of users) {
    const user = dbGet('skyid_users', login);
    if (user && user.token === auth) return res.json({ skyid: user.skyid, login });
  }
  res.status(401).json({ error:'Invalid token' });
});

// ========== Чат‑регистрация (мессенджер) ==========
app.post('/chat/register', (req,res) => {
  try {
    const { login, salt } = req.body;
    if (!login || !salt) return res.status(400).json({ error:'login and salt required' });
    if (dbGet('chat_users', login)) return res.status(409).json({ error:'User exists' });
    dbPut('chat_users', login, { salt, name: login, avatar: '', status: 'online' });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error:'Internal error' }); }
});

app.get('/chat/login_salt', (req,res) => {
  const login = req.query.login;
  if (!login) return res.status(400).json({ error:'login required' });
  const user = dbGet('chat_users', login);
  if (!user) return res.status(404).json({ error:'User not found' });
  res.json({ salt: user.salt });
});

// ========== Погода ==========
app.post('/api/weather', async (req,res) => {
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ error:'No data' });
    const payload = await decryptClientPayload(data);
    const city = payload.city;
    if (!city) return res.status(400).json({ error:'City required' });
    const weatherRes = await axios.get(`https://wttr.in/${encodeURIComponent(city)}?format=j1`, { timeout: 8000 });
    const current = weatherRes.data.current_condition[0];
    const answer = { temp: current.temp_C, desc: current.weatherDesc[0].value, city };
    const encWeather = await encryptClientResponse(answer);
    res.json({ data: encWeather });
  } catch(e) { res.status(500).json({ error:'Weather failed' }); }
});

// ========== Объявления ==========
app.get('/announcements', async (req,res) => {
  try {
    const keys = dbList('announcements');
    const list = keys.map(k => dbGet('announcements', k)).filter(Boolean).sort((a,b) => b.created - a.created);
    const encList = await encryptClientResponse(list);
    res.json({ data: encList });
  } catch(e) { res.status(500).json({ error:'Failed' }); }
});

app.post('/announcements', async (req,res) => {
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ error:'No data' });
    const payload = await decryptClientPayload(data);
    const text = payload.text;
    if (!text) return res.status(400).json({ error:'Text required' });

    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error:'Unauthorized' });
    const token = authHeader.split(' ')[1];
    // Проверка админа через SkyID
    const meUser = dbList('skyid_users').map(l => dbGet('skyid_users', l)).find(u => u && u.token === token);
    if (!meUser || meUser.login !== ADMIN_LOGIN) return res.status(403).json({ error:'Only SkyMonder can post' });

    const ann = { id: 'ann_' + Date.now(), text, created: Date.now() };
    dbPut('announcements', ann.id, ann);
    const encOk = await encryptClientResponse({ ok: true });
    res.json({ data: encOk });
  } catch(e) { res.status(500).json({ error:'Failed' }); }
});

// ========== Прокси ==========
app.get('/proxy', async (req,res) => {
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
    $('img[src]').each((i, el) => {
      const src = $(el).attr('src');
      if (src && !src.startsWith('data:')) {
        try {
          const absolute = new URL(src, targetUrl).href;
          $(el).attr('src', `/proxy?url=${encodeURIComponent(absolute)}`);
        } catch (e) {}
      }
    });
    $('head').prepend(`<base href="${targetUrl}">`);
    res.set(response.headers);
    res.send($.html());
  } catch (error) { res.status(500).send('Proxy error: ' + error.message); }
});

// ========== Поиск групп/каналов ==========
app.get('/search_groups', (req,res) => {
  const query = (req.query.q || '').toLowerCase();
  const chatIds = dbList('chats');
  const results = [];
  for (const id of chatIds) {
    const chat = dbGet('chats', id);
    if (!chat) continue;
    if ((chat.type === 'group' || chat.type === 'channel') && chat.name.toLowerCase().includes(query)) {
      results.push({ id, type: chat.type, name: chat.name, membersCount: chat.members.length });
    }
  }
  res.json(results);
});

// ========== Загрузка файлов ==========
app.get('/get_upload_token', (req,res) => {
  const token = crypto.randomBytes(16).toString('hex');
  uploadTokens[token] = { valid: true, created: Date.now() };
  res.json({ token });
});

app.post('/upload_file', upload.single('file'), (req,res) => {
  const token = req.headers['x-upload-token'];
  if (!token || !uploadTokens[token]?.valid) return res.status(403).json({ error:'Invalid token' });
  const file = req.file;
  if (!file) return res.status(400).json({ error:'No file' });
  const fileUrl = `/files/${file.filename}`;
  res.json({ url: fileUrl, name: file.originalname, size: file.size, type: file.mimetype });
});

app.get('/files/:filename', (req,res) => {
  const filePath = path.join(uploadDir, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('File not found');
  res.sendFile(filePath);
});

// ========== Spotify ==========
app.post('/spotify/token', async (req,res) => {
  try {
    const { code, code_verifier, redirect_uri } = req.body;
    const client_id = process.env.SPOTIFY_CLIENT_ID;
    const client_secret = process.env.SPOTIFY_CLIENT_SECRET;
    if (!code || !code_verifier || !client_id || !client_secret) return res.status(400).json({ error:'Missing params' });
    const params = new URLSearchParams({ grant_type:'authorization_code', code, redirect_uri, client_id, code_verifier });
    const response = await axios.post('https://accounts.spotify.com/api/token', params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: 'Basic ' + Buffer.from(client_id + ':' + client_secret).toString('base64')
      }
    });
    res.json(response.data);
  } catch(e) { res.status(500).json({ error:'Token exchange failed' }); }
});

app.post('/spotify/save-token', async (req,res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error:'Unauthorized' });
    const token = authHeader.split(' ')[1];
    const meUser = dbList('skyid_users').map(l => dbGet('skyid_users', l)).find(u => u && u.token === token);
    if (!meUser) return res.status(401).json({ error:'Invalid user' });
    const { spotify_token, spotify_refresh, expires_at } = req.body;
    if (!spotify_token) return res.status(400).json({ error:'Missing token' });
    const data = encryptForStorage(JSON.stringify({ access_token: spotify_token, refresh_token: spotify_refresh || null, expires_at: expires_at || null }));
    dbPut('spotify_tokens', meUser.login, JSON.parse(data)); // stored as encrypted blob
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error:'Internal error' }); }
});

app.get('/spotify/get-token', async (req,res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error:'Unauthorized' });
    const token = authHeader.split(' ')[1];
    const meUser = dbList('skyid_users').map(l => dbGet('skyid_users', l)).find(u => u && u.token === token);
    if (!meUser) return res.status(401).json({ error:'Invalid user' });
    const encryptedObj = dbGet('spotify_tokens', meUser.login);
    if (!encryptedObj) return res.json({ token: null });
    const decrypted = decryptFromStorage(encryptedObj.data ? encryptedObj.data : JSON.stringify(encryptedObj));
    if (!decrypted) return res.json({ token: null });
    const data = JSON.parse(decrypted);
    res.json({ access_token: data.access_token, refresh_token: data.refresh_token, expires_at: data.expires_at });
  } catch(e) { res.status(500).json({ error:'Internal error' }); }
});

// ========== Соцсеть ==========
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.status(401).json({ error:'Unauthorized' });
  const token = authHeader.split(' ')[1];
  const user = dbList('skyid_users').map(l => dbGet('skyid_users', l)).find(u => u && u.token === token);
  if (!user) return res.status(401).json({ error:'Invalid token' });
  req.skyid = user.skyid;
  req.login = user.login;
  req.isAdmin = (user.login === ADMIN_LOGIN);
  next();
}

function adminRequired(req, res, next) {
  if (!req.isAdmin) return res.status(403).json({ error:'Forbidden' });
  next();
}

app.get('/posts', verifyToken, (req,res) => {
  const ids = dbList('social_posts');
  const posts = ids.map(id => dbGet('social_posts', id)).filter(Boolean).sort((a,b) => b.created - a.created).slice(0,50);
  res.json(posts);
});

app.post('/posts', verifyToken, (req,res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error:'Text required' });
  const post = {
    id: 'post_' + Date.now(),
    skyid: req.skyid,
    author: req.login,
    text,
    created: Date.now(),
    likes: [],
    dislikes: [],
    comments: []
  };
  dbPut('social_posts', post.id, post);
  res.json(post);
});

app.delete('/posts/:id', verifyToken, (req,res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error:'Not found' });
  if (post.skyid !== req.skyid && !req.isAdmin) return res.status(403).json({ error:'Forbidden' });
  dbDelete('social_posts', req.params.id);
  res.json({ ok: true });
});

app.post('/posts/:id/like', verifyToken, (req,res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error:'Not found' });
  post.dislikes = post.dislikes.filter(id => id !== req.skyid);
  if (!post.likes.includes(req.skyid)) post.likes.push(req.skyid);
  else post.likes = post.likes.filter(id => id !== req.skyid);
  dbPut('social_posts', req.params.id, post);
  res.json({ likes: post.likes.length, dislikes: post.dislikes.length });
});

app.post('/posts/:id/dislike', verifyToken, (req,res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error:'Not found' });
  post.likes = post.likes.filter(id => id !== req.skyid);
  if (!post.dislikes.includes(req.skyid)) post.dislikes.push(req.skyid);
  else post.dislikes = post.dislikes.filter(id => id !== req.skyid);
  dbPut('social_posts', req.params.id, post);
  res.json({ likes: post.likes.length, dislikes: post.dislikes.length });
});

app.get('/posts/:id/comments', verifyToken, (req,res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error:'Not found' });
  res.json(post.comments || []);
});

app.post('/posts/:id/comments', verifyToken, (req,res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error:'Text required' });
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error:'Not found' });
  const comment = {
    id: 'comment_' + Date.now(),
    skyid: req.skyid,
    author: req.login,
    text,
    created: Date.now(),
    likes: [],
    dislikes: []
  };
  post.comments.push(comment);
  dbPut('social_posts', req.params.id, post);
  res.json(comment);
});

app.delete('/posts/:id/comments/:commentId', verifyToken, (req,res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error:'Not found' });
  const comment = post.comments.find(c => c.id === req.params.commentId);
  if (!comment) return res.status(404).json({ error:'Comment not found' });
  if (comment.skyid !== req.skyid && !req.isAdmin) return res.status(403).json({ error:'Forbidden' });
  post.comments = post.comments.filter(c => c.id !== req.params.commentId);
  dbPut('social_posts', req.params.id, post);
  res.json({ ok: true });
});

// Лайки комментариев
app.post('/posts/:id/comments/:commentId/like', verifyToken, (req,res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error:'Not found' });
  const comment = post.comments.find(c => c.id === req.params.commentId);
  if (!comment) return res.status(404).json({ error:'Comment not found' });
  comment.dislikes = comment.dislikes.filter(id => id !== req.skyid);
  if (!comment.likes.includes(req.skyid)) comment.likes.push(req.skyid);
  else comment.likes = comment.likes.filter(id => id !== req.skyid);
  dbPut('social_posts', req.params.id, post);
  res.json({ likes: comment.likes.length, dislikes: comment.dislikes.length });
});

app.post('/posts/:id/comments/:commentId/dislike', verifyToken, (req,res) => {
  const post = dbGet('social_posts', req.params.id);
  if (!post) return res.status(404).json({ error:'Not found' });
  const comment = post.comments.find(c => c.id === req.params.commentId);
  if (!comment) return res.status(404).json({ error:'Comment not found' });
  comment.likes = comment.likes.filter(id => id !== req.skyid);
  if (!comment.dislikes.includes(req.skyid)) comment.dislikes.push(req.skyid);
  else comment.dislikes = comment.dislikes.filter(id => id !== req.skyid);
  dbPut('social_posts', req.params.id, post);
  res.json({ likes: comment.likes.length, dislikes: comment.dislikes.length });
});

// Бан
app.post('/admin/ban', verifyToken, adminRequired, (req,res) => {
  const { skyid } = req.body;
  if (!skyid) return res.status(400).json({ error:'skyid required' });
  dbPut('social_bans', skyid, { skyid, bannedAt: Date.now() });
  res.json({ ok: true });
});

app.post('/admin/unban', verifyToken, adminRequired, (req,res) => {
  const { skyid } = req.body;
  dbDelete('social_bans', skyid);
  res.json({ ok: true });
});

// ========== Поиск (SkySearch) ==========
async function fetchDuckDuckGo(query) {
  const res = await axios.get('https://api.duckduckgo.com/', { params: { q: query, format:'json', no_html:1, skip_disambig:1 }, timeout:5000 });
  const d = res.data;
  const items = [];
  if (d.Abstract) items.push({ title: d.Heading || query, text: d.Abstract, url: d.AbstractURL || null });
  if (d.RelatedTopics) d.RelatedTopics.forEach(t => { if (t.Text) items.push({ title: t.Text.split(' - ')[0], text: t.Text, url: t.FirstURL || null, icon: t.Icon?.URL }); });
  return items;
}

async function fetchWikipedia(query) {
  const res = await axios.get('https://en.wikipedia.org/w/api.php', { params: { action:'query', list:'search', srsearch:query, format:'json', srlimit:3 }, timeout:5000 });
  const pages = res.data.query.search;
  const items = [];
  for (const p of pages) {
    try {
      const pageRes = await axios.get('https://en.wikipedia.org/w/api.php', { params: { action:'query', prop:'extracts|info', exintro:1, explaintext:1, inprop:'url', pageids:p.pageid, format:'json' }, timeout:5000 });
      const page = pageRes.data.query.pages[p.pageid];
      items.push({ title: page.title, text: (page.extract||'').substring(0,300)+'...', url: page.fullurl || `https://en.wikipedia.org/?curid=${p.pageid}` });
    } catch(e) {}
  }
  return items;
}

async function fetchGitHub(query) {
  const res = await axios.get('https://api.github.com/search/repositories', { params: { q:query, per_page:3 }, headers:{ Accept:'application/vnd.github.v3+json' }, timeout:5000 });
  return res.data.items.map(repo => ({ title: repo.full_name, text: repo.description||'', url: repo.html_url, icon: repo.owner.avatar_url }));
}

async function fetchStackExchange(query) {
  const key = process.env.STACKEXCHANGE_KEY;
  if (!key) return [];
  const res = await axios.get('https://api.stackexchange.com/2.3/search/advanced', { params: { key, site:'stackoverflow', q:query, pagesize:3, order:'desc', sort:'relevance', filter:'withbody' }, timeout:5000 });
  return res.data.items.map(q => ({ title: q.title, text: (q.body||'').replace(/<[^>]*>/g,'').substring(0,300)+'...', url: q.link }));
}

async function fetchOpenStreetMap(query) {
  const res = await axios.get('https://nominatim.openstreetmap.org/search', { params: { q:query, format:'json', limit:3 }, headers:{ 'User-Agent':'SkyCitadel/1.0' }, timeout:5000 });
  return res.data.map(place => ({ title: place.display_name, text: `Тип: ${place.type}, Категория: ${place.category}`, url: `https://www.openstreetmap.org/?mlat=${place.lat}&mlon=${place.lon}` }));
}

async function fetchOpenLibrary(query) {
  const res = await axios.get('https://openlibrary.org/search.json', { params: { q:query, limit:3 }, timeout:5000 });
  return res.data.docs.slice(0,3).map(book => ({ title: book.title, text: book.author_name ? `Автор(ы): ${book.author_name.join(', ')}` : '', url: `https://openlibrary.org${book.key}` }));
}

async function fetchQuote(query) {
  const tag = query.split(' ')[0].toLowerCase().replace(/[^a-z]/g, '');
  const res = await axios.get('https://api.quotable.io/quotes/random', { params: { tags:tag, limit:2 }, timeout:5000 });
  return res.data.map(q => ({ title: `Цитата от ${q.author}`, text: `“${q.content}”`, url: `https://quotable.io/quotes/${q._id}` }));
}

async function fetchNews(query) {
  const key = process.env.NEWSAPI_KEY;
  if (!key) return [];
  const res = await axios.get('https://newsapi.org/v2/everything', { params: { q:query, apiKey:key, pageSize:3, language:'ru' }, timeout:5000 });
  return res.data.articles.map(a => ({ title: a.title, text: a.description||'', url: a.url, icon: a.urlToImage }));
}

async function fetchCocktail(query) {
  const res = await axios.get('https://www.thecocktaildb.com/api/json/v1/1/search.php', { params: { s:query }, timeout:5000 });
  if (!res.data.drinks) return [];
  return res.data.drinks.slice(0,3).map(d => ({ title: d.strDrink, text: (d.strInstructions||'').substring(0,200)+'...', url: `https://www.thecocktaildb.com/drink/${d.idDrink}`, icon: d.strDrinkThumb }));
}

app.post('/api/search', async (req,res) => {
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ error:'No encrypted data' });
    const payload = await decryptClientPayload(data);
    const query = payload.query;
    if (!query) return res.status(400).json({ error:'Query required' });

    const sources = [
      { name:'DuckDuckGo', fn:() => fetchDuckDuckGo(query) },
      { name:'Wikipedia', fn:() => fetchWikipedia(query) },
      { name:'GitHub', fn:() => fetchGitHub(query) },
      { name:'StackExchange', fn:() => fetchStackExchange(query) },
      { name:'OpenStreetMap', fn:() => fetchOpenStreetMap(query) },
      { name:'OpenLibrary', fn:() => fetchOpenLibrary(query) },
      { name:'Quotes', fn:() => fetchQuote(query) },
      { name:'News', fn:() => fetchNews(query) },
      { name:'Cocktails', fn:() => fetchCocktail(query) }
    ];

    const allResults = [];
    for (const source of sources) {
      try {
        const results = await source.fn();
        allResults.push(...results.map(r => ({ ...r, source: source.name })));
      } catch(e) { console.warn(`${source.name} failed:`, e.message); }
    }
    const answer = { query, results: allResults.slice(0,20) };
    const encrypted = await encryptClientResponse(answer);
    res.json({ data: encrypted });
  } catch(e) { res.status(500).json({ error:'Search failed' }); }
});

// ========== Мессенджер (WebSocket) ==========
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const connections = {};
const chatListCache = new Map();

wss.on('connection', (ws) => {
  let currentUser = null;

  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch(e) { return; }

    if (msg.type === 'auth') {
      const user = dbGet('chat_users', msg.login);
      if (!user) return ws.send(JSON.stringify({ type:'error', message:'User not found' }));
      currentUser = msg.login;
      connections[currentUser] = ws;
      user.status = 'online';
      dbPut('chat_users', msg.login, user);
      ws.send(JSON.stringify({ type:'auth_ok', ...user, login: msg.login }));
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
        case 'search_user': {
          const allUsers = dbList('chat_users').filter(u => u !== currentUser && u.toLowerCase().includes((msg.query||'').toLowerCase()));
          ws.send(JSON.stringify({ type:'user_search_result', users: allUsers.map(u => ({ login: u })) }));
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
      }
    } catch(e) { ws.send(JSON.stringify({ type:'error', message:'Server error' })); }
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
    if (connections[user]) connections[user].send(JSON.stringify({ type:'chat_list', chats: cached.chats }));
    return;
  }
  const chatIds = dbList('chats');
  const list = {};
  for (const id of chatIds) {
    try {
      const chat = dbGet('chats', id);
      if (!chat || chat.hidden?.includes(user)) continue;
      if (!chat.members.includes(user)) continue;
      let displayName = chat.name;
      if (chat.type === 'private') displayName = chat.members.find(m => m !== user) || chat.name;
      list[id] = { id, type: chat.type, name: displayName, lastMsg: chat.messages?.slice(-1)[0]?.text?.slice(0,30) || '', blocked: chat.blocked?.includes(user) || false };
    } catch(e) {}
  }
  chatListCache.set(user, { chats: list, timestamp: Date.now() });
  if (connections[user]) connections[user].send(JSON.stringify({ type:'chat_list', chats: list }));
}

async function handleGetMessages(ws, user, chatId) {
  const chat = dbGet('chats', chatId);
  if (!chat || !chat.members.includes(user)) return ws.send(JSON.stringify({ type:'messages', messages: [] }));
  ws.send(JSON.stringify({ type:'messages', messages: chat.messages || [] }));
}

async function handleSendMessage(user, chatId, text, file) {
  const chat = dbGet('chats', chatId);
  if (!chat || !chat.members.includes(user)) return;
  const message = { from: user, text: text || '', time: Date.now() };
  if (file) message.file = { name: file.name, type: file.type, data: file.url || file.data, size: file.size };
  chat.messages = chat.messages || [];
  chat.messages.push(message);
  dbPut('chats', chatId, chat);
  chat.members.forEach(m => {
    if (m !== user && connections[m] && !chat.blocked?.includes(m)) {
      connections[m].send(JSON.stringify({ type:'message', chatId, ...message }));
    }
  });
}

async function createPrivateChat(u1, u2) {
  const user = dbGet('chat_users', u2);
  if (!user) return;
  const id = [u1, u2].sort().join('_');
  if (!dbGet('chats', id)) dbPut('chats', id, { type:'private', members:[u1, u2], messages:[], created: Date.now() });
  await sendChatList(u1);
  await sendChatList(u2);
  if (connections[u1]) connections[u1].send(JSON.stringify({ type:'chat_created', chatId: id }));
}

async function createGroup(user, name) {
  const id = 'group_' + Date.now();
  dbPut('chats', id, { type:'group', name, members:[user], messages:[], created: Date.now() });
  await sendChatList(user);
}

async function createChannel(user, name) {
  const id = 'channel_' + Date.now();
  dbPut('chats', id, { type:'channel', name, members:[user], messages:[], created: Date.now() });
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
  ws.send(JSON.stringify({ type:'profile_updated', profile }));
}

async function forwardSignaling(msg, fromUser) {
  const chat = dbGet('chats', msg.chatId);
  if (!chat) return;
  const other = chat.members.find(m => m !== fromUser);
  if (other && connections[other]) {
    connections[other].send(JSON.stringify({ ...msg, from: fromUser }));
  }
}

server.listen(PORT, () => console.log(`SkyMonolith running on port ${PORT}`));
