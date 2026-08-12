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
const NodeCache = require('node-cache');

const app = express();

// ====== Увеличение таймаутов ======
app.use((req, res, next) => {
  req.setTimeout(120000); // 2 минуты
  res.setTimeout(120000);
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

// ========== КЕШИРОВАНИЕ ==========
const userCache = new NodeCache({ stdTTL: 600, checkperiod: 120 });
const clientCache = new NodeCache({ stdTTL: 3600, checkperiod: 300 });
const tokenCache = new NodeCache({ stdTTL: 3600, checkperiod: 300 });

// Единое объявление announcementCache (ОДИН РАЗ)
const announcementCache = { data: null, time: 0 };

// Кешированные функции доступа
function getCachedUser(login) {
  let user = userCache.get(login);
  if (!user) {
    user = dbGet('skyid_users', login);
    if (user) userCache.set(login, user);
  }
  return user;
}
function getCachedClient(clientId) {
  let client = clientCache.get(clientId);
  if (!client) {
    client = dbGet('oauth_clients', clientId);
    if (client) clientCache.set(clientId, client);
  }
  return client;
}
function getCachedToken(token) {
  let record = tokenCache.get(token);
  if (!record) {
    record = dbGet('oauth_tokens', token);
    if (record) tokenCache.set(token, record);
  }
  return record;
}

// Индекс skyid -> login
let skyidIndex = null;
function buildSkyidIndex() {
  if (skyidIndex) return skyidIndex;
  skyidIndex = new Map();
  const logins = dbList('skyid_users');
  for (const login of logins) {
    const user = getCachedUser(login);
    if (user) skyidIndex.set(user.skyid, login);
  }
  return skyidIndex;
}
function getUserBySkyid(skyid) {
  const index = buildSkyidIndex();
  const login = index.get(skyid);
  if (login) return getCachedUser(login);
  return null;
}

// ---------- Новая таблица токенов (для быстрой проверки) ----------
function saveToken(token, login, expiresInSeconds = 7*24*3600) {
  const expires = Date.now() + expiresInSeconds * 1000;
  const data = { login, expires };
  dbPut('tokens', token, data);
  tokenCache.set(token, data);
}
function getTokenData(token) {
  let data = tokenCache.get(token);
  if (!data) {
    data = dbGet('tokens', token);
    if (data) tokenCache.set(token, data);
  }
  return data;
}
function deleteToken(token) {
  dbDelete('tokens', token);
  tokenCache.del(token);
}

// ========== OAuth Клиенты (для совместимости) ==========
function registerClient(clientId, secret, name, redirectUris, allowedScopes = ['profile']) {
  if (dbGet('oauth_clients', clientId)) return;
  dbPut('oauth_clients', clientId, {
    client_id: clientId,
    client_secret: secret,
    name,
    redirect_uris: redirectUris,
    allowed_scopes: allowedScopes,
    default_scopes: ['profile']
  });
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
    expires: Date.now() + 6000000 // 10 минут
  };
  return id;
}

const pendingAuth = {}; // code -> { skyid, client_id, scope, redirect_uri, expires }

// ========== Health ==========
app.get('/healthix', (req, res) => res.json({ status: 'ok' }));

// ========== SkyCounter ==========
const SITES = ['skycitadel.onrender.com', 'skycitadel.cc.cd'];
app.get('/checkvizit', (req, res) => {
  const site = req.query.site;
  if (!site) return res.status(400).json({ error: 'Missing site' });
  if (!SITES.includes(site)) return res.status(403).json({ error: 'Site not allowed' });
  const today = new Date().toISOString().split('T')[0];
  const visits = dbGet('visits', today) || [];
  if (!visits.includes(site)) { visits.push(site); dbPut('visits', today, visits); return res.json({ status: 'ok', site, date: today }); }
  res.json({ status: 'already_exists', site, date: today });
});

// ========== OAuth 2.1 Provider (оставлен для внешних клиентов) ==========
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, scope, state } = req.query;
  if (!client_id || !redirect_uri) return res.status(400).send('Missing client_id or redirect_uri');
  const client = getCachedClient(client_id);
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

  const user = getCachedUser(login);
  if (!user) return res.status(401).json({ error: 'Неверный логин или пароль' });
  // Ускоренная проверка пароля (уменьшено число итераций для прототипа)
  const hash = crypto.pbkdf2Sync(password, user.salt, 10000, 64, 'sha512').toString('hex');
  if (hash !== user.hash) return res.status(401).json({ error: 'Неверный логин или пароль' });

  const client = getCachedClient(client_id);
  if (!client) return res.status(400).json({ error: 'Invalid client' });

  const requestedScopes = scope ? scope.split(' ') : client.default_scopes;
  const sessionId = generateAuthSession(user, client_id, requestedScopes, redirect_uri, state);
  res.redirect(`/oauth/consent?session=${sessionId}`);
});

app.get('/oauth/consent', (req, res) => {
  const sessionId = req.query.session;
  const session = authSessions[sessionId];
  if (!session || session.expires < Date.now()) return res.status(400).send('Сессия истекла');
  const client = getCachedClient(session.client_id);
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
    expires: Date.now() + 600000 // тоже увеличим до 10 минут
  };
  delete authSessions[sessionId];
  const params = new URLSearchParams({ code, state: session.state || '' });
  res.redirect(`${session.redirect_uri}?${params.toString()}`);
});

app.post('/oauth/token', async (req, res) => {
  const { code, client_id, client_secret, redirect_uri } = req.body;
  if (!code || !client_id) return res.status(400).json({ error: 'Missing parameters' });
  const client = getCachedClient(client_id);
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
  dbPut('oauth_tokens', accessToken, authRecord);
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

app.get('/me', (req, res) => {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });

  const tokenRecord = getCachedToken(auth);
  if (!tokenRecord) return res.status(401).json({ error: 'Invalid token' });

  const user = getUserBySkyid(tokenRecord.user_skyid);
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

app.get('/oauth/authorizations', (req, res) => {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const tokenRecord = getCachedToken(auth);
  if (!tokenRecord) return res.status(401).json({ error: 'Invalid token' });

  const allTokens = dbList('oauth_tokens');
  const userAuths = allTokens.map(id => dbGet('oauth_tokens', id))
    .filter(rec => rec.user_skyid === tokenRecord.user_skyid);

  const result = {};
  userAuths.forEach(rec => {
    if (!result[rec.client_id]) {
      result[rec.client_id] = { client_id: rec.client_id, scope: [], first_issued: rec.created_at };
    }
    result[rec.client_id].scope = [...new Set([...result[rec.client_id].scope, ...rec.scope])];
  });
  for (const clientId in result) {
    const client = getCachedClient(clientId);
    result[clientId].name = client ? client.name : clientId;
  }
  res.json(Object.values(result));
});

app.delete('/oauth/authorizations/:client_id', (req, res) => {
  const auth = req.headers.authorization?.replace('Bearer ', '');
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const tokenRecord = getCachedToken(auth);
  if (!tokenRecord) return res.status(401).json({ error: 'Invalid token' });

  const clientId = req.params.client_id;
  const tokens = dbList('oauth_tokens');
  let deleted = 0;
  for (const id of tokens) {
    const rec = dbGet('oauth_tokens', id);
    if (rec.user_skyid === tokenRecord.user_skyid && rec.client_id === clientId) {
      dbDelete('oauth_tokens', id);
      tokenCache.del(id);
      deleted++;
    }
  }
  res.json({ ok: true, deleted });
});

// ========== Упрощённая аутентификация (SkyAuth) ==========
// Регистрация
app.post('/register', async (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'No data' });
  try {
    const payload = await decryptClientPayload(data);
    const { login, password } = payload;
    if (!login || !password) return res.status(400).json({ error: 'Login and password required' });
    if (getCachedUser(login)) return res.status(409).json({ error: 'User exists' });
    const salt = crypto.randomBytes(16).toString('base64');
    const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    const skyid = 'sid_' + crypto.randomBytes(8).toString('hex');
    const token = crypto.randomBytes(32).toString('hex');
    // Сохраняем пользователя
    dbPut('skyid_users', login, { skyid, login, salt, hash, token });
    userCache.set(login, { skyid, login, salt, hash, token });
    // Сохраняем токен в отдельную таблицу для быстрой проверки
    saveToken(token, login, 7*24*3600); // 7 дней
    // Обновляем индекс
    if (skyidIndex) skyidIndex.set(skyid, login);
    if (!dbGet('chat_users', login)) {
      dbPut('chat_users', login, { salt, name: login, avatar: '', status: 'online' });
    }
    const enc = await encryptClientResponse({ skyid, token });
    res.json({ data: enc });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Логин
app.post('/login', async (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: 'No data' });
  try {
    const payload = await decryptClientPayload(data);
    const { login, password } = payload;
    if (!login || !password) return res.status(400).json({ error: 'Login and password required' });
    const user = getCachedUser(login);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const hash = crypto.pbkdf2Sync(password, user.salt, 10000, 64, 'sha512').toString('hex');
    if (hash !== user.hash) return res.status(401).json({ error: 'Invalid credentials' });
    // Генерируем новый токен (сессия)
    const newToken = crypto.randomBytes(32).toString('hex');
    user.token = newToken;
    dbPut('skyid_users', login, user);
    userCache.set(login, user);
    // Сохраняем новый токен
    saveToken(newToken, login, 7*24*3600);
    // Удаляем старый токен из таблицы (необязательно, но для чистоты)
    // Можно удалить старый, если он был – но мы не знаем старый, так что оставляем
    const enc = await encryptClientResponse({ skyid: user.skyid, token: newToken });
    res.json({ data: enc });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Проверка токена (для внутренних сервисов)
app.post('/verify', async (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader?.replace('Bearer ', '') || req.body.token;
  if (!token) return res.status(400).json({ error: 'Token required' });

  const tokenData = getTokenData(token);
  if (!tokenData) return res.status(401).json({ error: 'Invalid token' });

  if (tokenData.expires < Date.now()) {
    deleteToken(token);
    return res.status(401).json({ error: 'Token expired' });
  }

  const user = getCachedUser(tokenData.login);
  if (!user) return res.status(401).json({ error: 'User not found' });

  res.json({ skyid: user.skyid, login: user.login });
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

// ========== Объявления (с кешированием) ==========
// announcementCache уже объявлен в разделе кеширования
app.get('/announcements', async (req, res) => {
  if (Date.now() - announcementCache.time < 60000 && announcementCache.data) {
    return res.json({ data: await encryptClientResponse(announcementCache.data) });
  }
  const keys = dbList('announcements');
  const list = keys.map(k => dbGet('announcements', k)).filter(Boolean).sort((a,b) => b.created - a.created);
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
  const users = dbList('skyid_users');
  let isAdmin = false;
  for (const login of users) {
    const u = getCachedUser(login);
    if (u && u.token === auth && u.login === ADMIN_LOGIN) { isAdmin = true; break; }
  }
  if (!isAdmin) return res.status(403).json({ error: 'Forbidden' });
  const ann = { id: 'ann_' + Date.now(), text, created: Date.now() };
  dbPut('announcements', ann.id, ann);
  // Инвалидируем кеш
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
  for (const l of users) { const u = getCachedUser(l); if (u && u.token === auth) { login = l; break; } }
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
  for (const l of users) { const u = getCachedUser(l); if (u && u.token === auth) { login = l; break; } }
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
  // Сначала проверяем OAuth-токен
  const oauthRec = getCachedToken(auth);
  if (oauthRec) {
    const user = getUserBySkyid(oauthRec.user_skyid);
    if (user) {
      req.skyid = user.skyid;
      req.login = user.login;
      req.isAdmin = (user.login === ADMIN_LOGIN);
      return next();
    }
  }
  // fallback: проверяем простой токен (из таблицы tokens)
  const tokenData = getTokenData(auth);
  if (tokenData && tokenData.expires > Date.now()) {
    const user = getCachedUser(tokenData.login);
    if (user) {
      req.skyid = user.skyid;
      req.login = user.login;
      req.isAdmin = (user.login === ADMIN_LOGIN);
      return next();
    }
  }
  // И последний fallback: старый токен из skyid_users (перебор, медленно, но для обратной совместимости)
  const users = dbList('skyid_users');
  for (const login of users) {
    const user = getCachedUser(login);
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

// ========== Поиск (SkySearch) – заглушка ==========
app.post('/api/search', async (req, res) => {
  res.json({ data: await encryptClientResponse({ query: '', results: [] }) });
});

// ========== WebSocket (мессенджер) ==========
const server = http.createServer(app);
server.timeout = 120000; // 2 минуты

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

// ====== Запуск ======
server.listen(PORT, () => console.log(`SkyCitadel running on port ${PORT}`));
