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

// ====== Увеличение таймаутов ======
app.use((req, res, next) => {
  req.setTimeout(120000);
  res.setTimeout(120000);
  next();
});

// ====== Логирование времени ======
app.use((req, res, next) => {
  const start = Date.now();
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} started`);
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} finished in ${duration}ms`);
  });
  next();
});

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

// ---------- Асинхронная файловая БД с кешированием списков ----------
const DATA_DIR = path.join(__dirname, 'data');
(async () => {
  try { await fs.mkdir(DATA_DIR, { recursive: true }); } catch (e) {}
})();

const listCache = new Map(); // bucket -> { keys: [], timestamp: number }

async function ensureBucketDir(bucket) {
  const dir = path.join(DATA_DIR, bucket);
  try { await fs.mkdir(dir, { recursive: true }); } catch (e) {}
  return dir;
}

async function dbPut(bucket, key, data) {
  const dir = await ensureBucketDir(bucket);
  const filePath = path.join(dir, key + '.json');
  await fs.writeFile(filePath, JSON.stringify(data, null, 2));
  listCache.delete(bucket);
}

async function dbGet(bucket, key) {
  const filePath = path.join(DATA_DIR, bucket, key + '.json');
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(content);
  } catch (e) {
    return null;
  }
}

async function dbList(bucket) {
  const cached = listCache.get(bucket);
  if (cached && (Date.now() - cached.timestamp < 2000)) {
    return cached.keys;
  }
  const dir = path.join(DATA_DIR, bucket);
  try {
    await fs.mkdir(dir, { recursive: true });
    const files = await fs.readdir(dir);
    const keys = files.filter(f => f.endsWith('.json')).map(f => f.slice(0, -5));
    listCache.set(bucket, { keys, timestamp: Date.now() });
    return keys;
  } catch (e) {
    return [];
  }
}

async function dbDelete(bucket, key) {
  const filePath = path.join(DATA_DIR, bucket, key + '.json');
  try { await fs.unlink(filePath); } catch (e) {}
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

// ========== КЕШИРОВАНИЕ (in-memory) ==========
const userCache = new NodeCache({ stdTTL: 600, checkperiod: 120 });
const clientCache = new NodeCache({ stdTTL: 3600, checkperiod: 300 });
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
async function getCachedClient(clientId) {
  let client = clientCache.get(clientId);
  if (!client) {
    client = await dbGet('oauth_clients', clientId);
    if (client) clientCache.set(clientId, client);
  }
  return client;
}
async function getCachedToken(token) {
  let record = tokenCache.get(token);
  if (!record) {
    record = await dbGet('oauth_tokens', token);
    if (record) tokenCache.set(token, record);
  }
  return record;
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
  const data = { login, expires };
  await dbPut('tokens', token, data);
  tokenCache.set(token, data);
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

// ========== OAuth Клиенты (для совместимости) ==========
function registerClient(clientId, secret, name, redirectUris, allowedScopes = ['profile']) {
  (async () => {
    if (await dbGet('oauth_clients', clientId)) return;
    await dbPut('oauth_clients', clientId, {
      client_id: clientId,
      client_secret: secret,
      name,
      redirect_uris: redirectUris,
      allowed_scopes: allowedScopes,
      default_scopes: ['profile']
    });
  })();
}

registerClient('skyvideo', 'skyvideo_secret', 'SkyVideo',
  [
    'https://skyvideo.onrender.com/auth/callback',
    'https://skycitadel.onrender.com/callback.html',
    'https://skycitadel.cc.cd/callback.html'
  ],
  ['profile', 'email']
);

registerClient('skysocial', 'skysocial_secret', 'SkySocial',
  [
    'https://skycitadel.onrender.com/socnet.html',
    'https://skycitadel.cc.cd/socnet.html',
    'https://skycitadel.cc.cd/callback_social.html'
  ],
  ['profile', 'social']
);

const authSessions = {};
function generateAuthSession(user, clientId, scope, redirectUri, state) {
  const id = crypto.randomBytes(16).toString('hex');
  authSessions[id] = {
    user_skyid: user.skyid,
    client_id: clientId,
    scope,
    redirect_uri: redirectUri,
    state,
    expires: Date.now() + 6000000
  };
  return id;
}
const pendingAuth = {};

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

// ========== OAuth 2.1 Provider (для внешних клиентов) ==========
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, scope, state } = req.query;
  if (!client_id || !redirect_uri) return res.status(400).send('Missing client_id or redirect_uri');
  const client = clientCache.get(client_id);
  if (!client) return res.status(400).send('Invalid client_id');
  if (!client.redirect_uris.includes(redirect_uri)) return res.status(400).send('Invalid redirect_uri');
  const requestedScopes = scope ? scope.split(' ') : client.default_scopes;
  const invalidScopes = requestedScopes.filter(s => !client.allowed_scopes.includes(s));
  if (invalidScopes.length) return res.status(400).send('Invalid scope(s): ' + invalidScopes.join(', '));

  res.send(`<!DOCTYPE html>
    <html lang="ru">
    <head><meta charset="UTF-8"><title>SkyID — Вход</title>
    <style>
      body { background: #0a0f1e; color: #e0e8ff; font-family: 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
      .card { background: #1a233a; padding: 2rem; border-radius: 20px; border: 1px solid #2a3450; text-align: center; }
      input { width: 100%; padding: 0.7rem; margin: 0.5rem 0; background: #0d1225; border: 1px solid #3a4660; color: white; border-radius: 10px; }
      .btn { background: #5f7ecf; border: none; color: white; padding: 0.7rem 1.5rem; border-radius: 10px; cursor: pointer; font-weight: bold; margin-top: 0.5rem; }
      .error { color: #f48024; margin-top: 0.5rem; }
    </style></head>
    <body>
      <div class="card">
        <h2>Вход в SkyID</h2>
        <p>Приложение запрашивает доступ к вашему идентификатору</p>
        <form action="/oauth/authorize" method="POST">
          <input type="hidden" name="client_id" value="${client_id}">
          <input type="hidden" name="redirect_uri" value="${redirect_uri}">
          <input type="hidden" name="scope" value="${requestedScopes.join(' ')}">
          <input type="hidden" name="state" value="${state || ''}">
          <input type="text" name="login" placeholder="Логин" required>
          <input type="password" name="password" placeholder="Пароль" required>
          <button type="submit" class="btn">Войти</button>
        </form>
        <div class="error" id="error"></div>
      </div>
    </body>
    </html>
  `);
});

app.post('/oauth/authorize', async (req, res) => {
  const { login, password, client_id, redirect_uri, scope, state } = req.body;
  if (!login || !password || !client_id || !redirect_uri) return res.status(400).json({ error: 'Missing fields' });

  const user = await getCachedUser(login);
  if (!user) return res.status(401).json({ error: 'Неверный логин или пароль' });
  const hash = await new Promise((resolve, reject) => {
    crypto.pbkdf2(password, user.salt, 10000, 64, 'sha512', (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey.toString('hex'));
    });
  });
  if (hash !== user.hash) return res.status(401).json({ error: 'Неверный логин или пароль' });

  const client = await getCachedClient(client_id);
  if (!client) return res.status(400).json({ error: 'Invalid client' });

  const requestedScopes = scope ? scope.split(' ') : client.default_scopes;
  const sessionId = generateAuthSession(user, client_id, requestedScopes, redirect_uri, state);
  res.redirect(`/oauth/consent?session=${sessionId}`);
});

app.get('/oauth/consent', (req, res) => {
  const sessionId = req.query.session;
  const session = authSessions[sessionId];
  if (!session || session.expires < Date.now()) return res.status(400).send('Сессия истекла');
  const client = clientCache.get(session.client_id);
  if (!client) return res.status(400).send('Клиент не найден');
  const scopeDescriptions = {
    'profile': 'Ваше имя и аватар',
    'email': 'Ваш адрес электронной почты',
    'phone': 'Ваш номер телефона',
    'social': 'Доступ к публикациям и комментариям'
  };
  const scopeListHtml = session.scope.map(s => `<li>${scopeDescriptions[s] || s}</li>`).join('');
  res.send(`<!DOCTYPE html>
    <html lang="ru">
    <head><meta charset="UTF-8"><title>Запрос доступа</title>
    <style>
      body { background: #0a0f1e; color: #e0e8ff; font-family: 'Segoe UI', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
      .card { background: #1a233a; padding: 2rem; border-radius: 20px; border: 1px solid #2a3450; max-width: 500px; width: 100%; }
      h2 { color: #b7ceff; }
      ul { list-style: none; padding: 0; }
      li { padding: 0.5rem; border-bottom: 1px solid #2a3450; }
      .btn-row { display: flex; gap: 1rem; justify-content: center; margin-top: 1.5rem; }
      .btn { padding: 0.7rem 2rem; border: none; border-radius: 10px; cursor: pointer; font-weight: bold; }
      .allow { background: #5f7ecf; color: white; }
      .deny { background: #6b4c4c; color: white; }
    </style>
    </head>
    <body>
      <div class="card">
        <h2>${client.name} запрашивает доступ</h2>
        <p>Приложение хочет получить:</p>
        <ul>${scopeListHtml}</ul>
        <form action="/oauth/consent" method="POST">
          <input type="hidden" name="session" value="${sessionId}">
          <div class="btn-row">
            <button type="submit" name="action" value="allow" class="btn allow">Разрешить</button>
            <button type="submit" name="action" value="deny" class="btn deny">Отказать</button>
          </div>
        </form>
      </div>
    </body>
    </html>
  `);
});

app.post('/oauth/consent', (req, res) => {
  const { session: sessionId, action } = req.body;
  const session = authSessions[sessionId];
  if (!session || session.expires < Date.now()) return res.status(400).send('Сессия истекла');
  if (action === 'deny') {
    const params = new URLSearchParams({ error: 'access_denied', state: session.state || '' });
    return res.redirect(`${session.redirect_uri}?${params.toString()}`);
  }
  const code = crypto.randomBytes(16).toString('hex');
  pendingAuth[code] = {
    skyid: session.user_skyid,
    client_id: session.client_id,
    scope: session.scope,
    redirect_uri: session.redirect_uri,
    expires: Date.now() + 600000
  };
  delete authSessions[sessionId];
  const params = new URLSearchParams({ code, state: session.state || '' });
  res.redirect(`${session.redirect_uri}?${params.toString()}`);
});

app.post('/oauth/token', async (req, res) => {
  const { code, client_id, client_secret, redirect_uri } = req.body;
  if (!code || !client_id) return res.status(400).json({ error: 'Missing parameters' });
  const client = await getCachedClient(client_id);
  if (!client) return res.status(400).json({ error: 'Invalid client' });
  if (redirect_uri && !client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'Invalid redirect_uri' });
  }
  const pending = pendingAuth[code];
  if (!pending || pending.expires < Date.now()) {
    delete pendingAuth[code];
    return res.status(400).json({ error: 'Invalid or expired code' });
  }
  if (pending.client_id !== client_id) {
    return res.status(400).json({ error: 'Client mismatch' });
  }

  const accessToken = crypto.randomBytes(32).toString('hex');
  const authRecord = {
    user_skyid: pending.skyid,
    client_id: client_id,
    scope: pending.scope,
    access_token: accessToken,
    created_at: Date.now()
  };
  await dbPut('oauth_tokens', accessToken, authRecord);
  tokenCache.set(accessToken, authRecord);

  delete pendingAuth[code];
  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: pending.scope.join(' '),
    skyid: pending.skyid
  });
});

app.get('/me', async (req, res) => {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });

  const tokenRecord = await getCachedToken(auth);
  if (!tokenRecord) return res.status(401).json({ error: 'Invalid token' });

  const user = await getUserBySkyid(tokenRecord.user_skyid);
  if (!user) return res.status(401).json({ error: 'User not found' });

  const result = { skyid: user.skyid };
  if (tokenRecord.scope.includes('profile')) {
    result.login = user.login;
    result.name = user.name || user.login;
    result.avatar = user.avatar || '';
  }
  if (tokenRecord.scope.includes('email')) {
    result.email = user.email || '';
  }
  if (tokenRecord.scope.includes('phone')) {
    result.phone = user.phone || '';
  }
  res.json(result);
});

app.get('/oauth/authorizations', async (req, res) => {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const tokenRecord = await getCachedToken(auth);
  if (!tokenRecord) return res.status(401).json({ error: 'Invalid token' });

  const allTokens = await dbList('oauth_tokens');
  const userAuths = [];
  for (const id of allTokens) {
    const rec = await dbGet('oauth_tokens', id);
    if (rec && rec.user_skyid === tokenRecord.user_skyid) userAuths.push(rec);
  }

  const result = {};
  userAuths.forEach(rec => {
    if (!result[rec.client_id]) {
      result[rec.client_id] = { client_id: rec.client_id, scope: [], first_issued: rec.created_at };
    }
    result[rec.client_id].scope = [...new Set([...result[rec.client_id].scope, ...rec.scope])];
  });
  for (const clientId in result) {
    const client = await getCachedClient(clientId);
    result[clientId].name = client ? client.name : clientId;
  }
  res.json(Object.values(result));
});

app.delete('/oauth/authorizations/:client_id', async (req, res) => {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const tokenRecord = await getCachedToken(auth);
  if (!tokenRecord) return res.status(401).json({ error: 'Invalid token' });

  const clientId = req.params.client_id;
  const tokens = await dbList('oauth_tokens');
  let deleted = 0;
  for (const id of tokens) {
    const rec = await dbGet('oauth_tokens', id);
    if (rec && rec.user_skyid === tokenRecord.user_skyid && rec.client_id === clientId) {
      await dbDelete('oauth_tokens', id);
      tokenCache.del(id);
      deleted++;
    }
  }
  res.json({ ok: true, deleted });
});

// ========== Упрощённая аутентификация (SkyAuth) с JWT ==========
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

// ========== Объявления (с кешированием) ==========
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

  const oauthRec = await getCachedToken(auth);
  if (oauthRec) {
    const user = await getUserBySkyid(oauthRec.user_skyid);
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

// ========== Поиск (SkySearch) – заглушка ==========
app.post('/api/search', async (req, res) => {
  res.json({ data: await encryptClientResponse({ query: '', results: [] }) });
});

// ========== WebSocket (мессенджер) ==========
const server = http.createServer(app);
server.timeout = 120000;

const wss = new WebSocket.Server({ server });
const connections = {};
const chatListCache = new Map();

wss.on('connection', (ws) => {
  let currentUser = null;
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

server.listen(PORT, () => console.log(`SkyMutant running on port ${PORT}`));
