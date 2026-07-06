// SkyCitadel Worker – вся крепость в одном файле
// Требует: KV namespace (SKYCITADEL_KV) и Durable Object (SkyChatDO)

// ---------- Конфигурация ----------
const ADMIN_LOGIN = 'SkyMonder';
const CLIENT_SECRET = "BLx5Vp7U1c8dR2mQkG4fJ6yA9tC3bF0zH7iL2nM5oP8=";
const CLIENT_KEY = base64ToArrayBuffer(CLIENT_SECRET);
const STORAGE_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // замени на свой!
const STORAGE_KEY = hexToArrayBuffer(STORAGE_KEY_HEX);

// ---------- Шифрование (Web Crypto) ----------
function hexToArrayBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i/2] = parseInt(hex.substr(i, 2), 16);
  return bytes.buffer;
}
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
async function encryptForStorage(plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', STORAGE_KEY, { name: 'AES-GCM' }, false, ['encrypt']);
  const encoded = new TextEncoder().encode(plaintext);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.byteLength);
  return btoa(String.fromCharCode(...combined));
}
async function decryptFromStorage(combinedBase64) {
  try {
    const combined = Uint8Array.from(atob(combinedBase64), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const data = combined.slice(12);
    const key = await crypto.subtle.importKey('raw', STORAGE_KEY, { name: 'AES-GCM' }, false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(decrypted);
  } catch (e) { return null; }
}
async function decryptClientPayload(combinedBase64) {
  const combined = Uint8Array.from(atob(combinedBase64), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const data = combined.slice(12);
  const key = await crypto.subtle.importKey('raw', CLIENT_KEY, { name: 'AES-GCM' }, false, ['decrypt']);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return JSON.parse(new TextDecoder().decode(decrypted));
}
async function encryptClientResponse(plainObj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', CLIENT_KEY, { name: 'AES-GCM' }, false, ['encrypt']);
  const encoded = new TextEncoder().encode(JSON.stringify(plainObj));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.byteLength);
  return btoa(String.fromCharCode(...combined));
}

// ---------- KV хелперы ----------
async function kvGet(bucket, key) {
  const raw = await SKYCITADEL_KV.get(`${bucket}:${key}`);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return raw; }
}
async function kvPut(bucket, key, value) {
  await SKYCITADEL_KV.put(`${bucket}:${key}`, JSON.stringify(value));
}
async function kvList(bucket) {
  const list = await SKYCITADEL_KV.list({ prefix: `${bucket}:` });
  return list.keys.map(k => k.name.replace(`${bucket}:`, ''));
}
async function kvDelete(bucket, key) {
  await SKYCITADEL_KV.delete(`${bucket}:${key}`);
}

// ---------- Обработчики REST ----------
async function handleRegister(request) {
  const { data } = await request.json();
  if (!data) return new Response('{"error":"No data"}', { status: 400 });
  const payload = await decryptClientPayload(data);
  const { login, password } = payload;
  if (!login || !password) return new Response('{"error":"login/password required"}', { status: 400 });
  if (await kvGet('skyid_users', login)) return new Response('{"error":"User exists"}', { status: 409 });
  const salt = crypto.getRandomValues(new Uint8Array(16)).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');
  const hash = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(password + salt));
  const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  const skyid = 'sky_' + crypto.randomUUID().slice(0, 8);
  const token = crypto.randomUUID();
  await kvPut('skyid_users', login, { skyid, salt, hash: hashHex, token, name: login, avatar: '', status: 'online' });
  const answer = { skyid, token };
  const encResponse = await encryptClientResponse(answer);
  return Response.json({ data: encResponse });
}

async function handleLogin(request) {
  const { data } = await request.json();
  if (!data) return new Response('{"error":"No data"}', { status: 400 });
  const payload = await decryptClientPayload(data);
  const { login, password } = payload;
  if (!login || !password) return new Response('{"error":"login/password required"}', { status: 400 });
  const user = await kvGet('skyid_users', login);
  if (!user) return new Response('{"error":"User not found"}', { status: 404 });
  const hash = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(password + user.salt));
  const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  if (hashHex !== user.hash) return new Response('{"error":"Invalid password"}', { status: 401 });
  const token = crypto.randomUUID();
  user.token = token;
  await kvPut('skyid_users', login, user);
  const answer = { skyid: user.skyid, token };
  const encResponse = await encryptClientResponse(answer);
  return Response.json({ data: encResponse });
}

async function handleMe(request) {
  const auth = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!auth) return new Response('{"error":"Unauthorized"}', { status: 401 });
  const logins = await kvList('skyid_users');
  for (const login of logins) {
    const user = await kvGet('skyid_users', login);
    if (user && user.token === auth) return Response.json({ skyid: user.skyid, login });
  }
  return new Response('{"error":"Invalid token"}', { status: 401 });
}

async function handleChatRegister(request) {
  const { login, salt } = await request.json();
  if (!login || !salt) return new Response('{"error":"login and salt required"}', { status: 400 });
  if (await kvGet('chat_users', login)) return new Response('{"error":"User exists"}', { status: 409 });
  await kvPut('chat_users', login, { salt, name: login, avatar: '', status: 'online' });
  return Response.json({ ok: true });
}

async function handleChatLoginSalt(request) {
  const login = new URL(request.url).searchParams.get('login');
  if (!login) return new Response('{"error":"login required"}', { status: 400 });
  const user = await kvGet('chat_users', login);
  if (!user) return new Response('{"error":"User not found"}', { status: 404 });
  return Response.json({ salt: user.salt });
}

async function handleWeather(request) {
  const { data } = await request.json();
  if (!data) return new Response('{"error":"No data"}', { status: 400 });
  const payload = await decryptClientPayload(data);
  const city = payload.city;
  if (!city) return new Response('{"error":"City required"}', { status: 400 });
  const res = await fetch(`https://wttr.in/${encodeURIComponent(city)}?format=j1`);
  const json = await res.json();
  const current = json.current_condition[0];
  const answer = { temp: current.temp_C, desc: current.weatherDesc[0].value, city };
  const enc = await encryptClientResponse(answer);
  return Response.json({ data: enc });
}

async function getAnnouncements() {
  const keys = await kvList('announcements');
  const list = keys.map(k => kvGet('announcements', k)).filter(Boolean).sort((a,b) => b.created - a.created);
  const enc = await encryptClientResponse(list);
  return Response.json({ data: enc });
}

async function postAnnouncement(request) {
  const { data } = await request.json();
  if (!data) return new Response('{"error":"No data"}', { status: 400 });
  const payload = await decryptClientPayload(data);
  const text = payload.text;
  if (!text) return new Response('{"error":"Text required"}', { status: 400 });
  const auth = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!auth) return new Response('{"error":"Unauthorized"}', { status: 401 });
  const logins = await kvList('skyid_users');
  let isAdmin = false;
  for (const login of logins) {
    const user = await kvGet('skyid_users', login);
    if (user && user.token === auth && user.login === ADMIN_LOGIN) { isAdmin = true; break; }
  }
  if (!isAdmin) return new Response('{"error":"Forbidden"}', { status: 403 });
  const ann = { id: 'ann_' + Date.now(), text, created: Date.now() };
  await kvPut('announcements', ann.id, ann);
  const enc = await encryptClientResponse({ ok: true });
  return Response.json({ data: enc });
}

async function searchGroups(request) {
  const q = (new URL(request.url).searchParams.get('q') || '').toLowerCase();
  const chatIds = await kvList('chats');
  const results = [];
  for (const id of chatIds) {
    const chat = await kvGet('chats', id);
    if (!chat) continue;
    if ((chat.type === 'group' || chat.type === 'channel') && chat.name.toLowerCase().includes(q)) {
      results.push({ id, type: chat.type, name: chat.name, membersCount: chat.members.length });
    }
  }
  return Response.json(results);
}

async function uploadFile(request) {
  const formData = await request.formData();
  const file = formData.get('file');
  if (!file) return new Response('{"error":"No file"}', { status: 400 });
  const key = 'file_' + Date.now() + '_' + Math.random().toString(36).slice(2,8);
  await SKYCITADEL_KV.put(key, file.stream, { metadata: { filename: file.name, type: file.type } });
  return Response.json({ url: '/files/' + key, name: file.name, size: file.size, type: file.type });
}

// Spotify
async function spotifyToken(request) {
  const { code, code_verifier, redirect_uri } = await request.json();
  const client_id = SPOTIFY_CLIENT_ID;
  const client_secret = SPOTIFY_CLIENT_SECRET;
  if (!code || !code_verifier || !client_id || !client_secret) return new Response('{"error":"Missing params"}', { status: 400 });
  const params = new URLSearchParams({ grant_type:'authorization_code', code, redirect_uri, client_id, code_verifier });
  const res = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: 'Basic ' + btoa(client_id + ':' + client_secret) },
    body: params.toString()
  });
  return Response.json(await res.json());
}

async function spotifySaveToken(request) {
  const auth = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!auth) return new Response('{"error":"Unauthorized"}', { status: 401 });
  const logins = await kvList('skyid_users');
  let login;
  for (const l of logins) {
    const u = await kvGet('skyid_users', l);
    if (u && u.token === auth) { login = l; break; }
  }
  if (!login) return new Response('{"error":"Invalid user"}', { status: 401 });
  const { spotify_token, spotify_refresh, expires_at } = await request.json();
  if (!spotify_token) return new Response('{"error":"Missing token"}', { status: 400 });
  const enc = await encryptForStorage(JSON.stringify({ access_token: spotify_token, refresh_token: spotify_refresh || null, expires_at: expires_at || null }));
  await kvPut('spotify_tokens', login, enc);
  return Response.json({ ok: true });
}

async function spotifyGetToken(request) {
  const auth = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!auth) return new Response('{"error":"Unauthorized"}', { status: 401 });
  const logins = await kvList('skyid_users');
  let login;
  for (const l of logins) {
    const u = await kvGet('skyid_users', l);
    if (u && u.token === auth) { login = l; break; }
  }
  if (!login) return new Response('{"error":"Invalid user"}', { status: 401 });
  const enc = await kvGet('spotify_tokens', login);
  if (!enc) return Response.json({ token: null });
  const data = JSON.parse(await decryptFromStorage(enc));
  return Response.json({ access_token: data.access_token, refresh_token: data.refresh_token, expires_at: data.expires_at });
}

// Соцсеть
async function getPosts(request) {
  const ids = await kvList('social_posts');
  const posts = (await Promise.all(ids.map(id => kvGet('social_posts', id)))).filter(Boolean).sort((a,b) => b.created - a.created).slice(0,50);
  return Response.json(posts);
}
async function createPost(request) {
  const auth = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!auth) return new Response('{"error":"Unauthorized"}', { status: 401 });
  const logins = await kvList('skyid_users');
  let user;
  for (const l of logins) { const u = await kvGet('skyid_users', l); if (u && u.token === auth) { user = u; break; } }
  if (!user) return new Response('{"error":"Invalid token"}', { status: 401 });
  const { text } = await request.json();
  if (!text) return new Response('{"error":"Text required"}', { status: 400 });
  const post = { id: 'post_' + Date.now(), skyid: user.skyid, author: user.login, text, created: Date.now(), likes: [], dislikes: [], comments: [] };
  await kvPut('social_posts', post.id, post);
  return Response.json(post);
}
async function likePost(request, path) {
  const auth = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!auth) return new Response('{"error":"Unauthorized"}', { status: 401 });
  const logins = await kvList('skyid_users');
  let user;
  for (const l of logins) { const u = await kvGet('skyid_users', l); if (u && u.token === auth) { user = u; break; } }
  if (!user) return new Response('{"error":"Invalid token"}', { status: 401 });
  const postId = path.split('/')[2];
  const post = await kvGet('social_posts', postId);
  if (!post) return new Response('{"error":"Not found"}', { status: 404 });
  post.dislikes = post.dislikes.filter(id => id !== user.skyid);
  if (!post.likes.includes(user.skyid)) post.likes.push(user.skyid);
  else post.likes = post.likes.filter(id => id !== user.skyid);
  await kvPut('social_posts', postId, post);
  return Response.json({ likes: post.likes.length, dislikes: post.dislikes.length });
}
async function comments(request, path) {
  const auth = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!auth) return new Response('{"error":"Unauthorized"}', { status: 401 });
  const logins = await kvList('skyid_users');
  let user;
  for (const l of logins) { const u = await kvGet('skyid_users', l); if (u && u.token === auth) { user = u; break; } }
  if (!user) return new Response('{"error":"Invalid token"}', { status: 401 });
  const postId = path.split('/')[2];
  const post = await kvGet('social_posts', postId);
  if (!post) return new Response('{"error":"Not found"}', { status: 404 });
  if (request.method === 'GET') return Response.json(post.comments || []);
  if (request.method === 'POST') {
    const { text } = await request.json();
    if (!text) return new Response('{"error":"Text required"}', { status: 400 });
    const comment = { id: 'comment_' + Date.now(), skyid: user.skyid, author: user.login, text, created: Date.now(), likes: [], dislikes: [] };
    post.comments.push(comment);
    await kvPut('social_posts', postId, post);
    return Response.json(comment);
  }
  return new Response('{"error":"Method not allowed"}', { status: 405 });
}
async function banUser(request) {
  const auth = request.headers.get('Authorization')?.replace('Bearer ', '');
  if (!auth) return new Response('{"error":"Unauthorized"}', { status: 401 });
  const logins = await kvList('skyid_users');
  let user;
  for (const l of logins) { const u = await kvGet('skyid_users', l); if (u && u.token === auth) { user = u; break; } }
  if (!user || user.login !== ADMIN_LOGIN) return new Response('{"error":"Forbidden"}', { status: 403 });
  const { skyid } = await request.json();
  if (!skyid) return new Response('{"error":"skyid required"}', { status: 400 });
  await kvPut('social_bans', skyid, { skyid, bannedAt: Date.now() });
  return Response.json({ ok: true });
}

// Поиск
async function search(request) {
  const { data } = await request.json();
  if (!data) return new Response('{"error":"No data"}', { status: 400 });
  const payload = await decryptClientPayload(data);
  const query = payload.query;
  if (!query) return new Response('{"error":"Query required"}', { status: 400 });
  const results = await Promise.allSettled([
    fetchDuckDuckGo(query), fetchWikipedia(query), fetchGitHub(query),
    fetchStackExchange(query), fetchOpenStreetMap(query), fetchOpenLibrary(query),
    fetchQuote(query), fetchNews(query), fetchCocktail(query)
  ]);
  const all = [];
  results.forEach(r => { if (r.status === 'fulfilled') all.push(...r.value); });
  const enc = await encryptClientResponse({ query, results: all.slice(0,20) });
  return Response.json({ data: enc });
}

// функции поиска (сокращены, но рабочие)
async function fetchDuckDuckGo(q) {
  const res = await fetch(`https://api.duckduckgo.com/?q=${encodeURIComponent(q)}&format=json&no_html=1&skip_disambig=1`);
  const d = await res.json();
  const items = [];
  if (d.Abstract) items.push({ title: d.Heading || q, text: d.Abstract, url: d.AbstractURL, source: 'DuckDuckGo' });
  if (d.RelatedTopics) d.RelatedTopics.forEach(t => { if (t.Text) items.push({ title: t.Text.split(' - ')[0], text: t.Text, url: t.FirstURL, icon: t.Icon?.URL, source: 'DuckDuckGo' }); });
  return items;
}
async function fetchWikipedia(q) {
  const res = await fetch(`https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(q)}&format=json&srlimit=3`);
  const pages = (await res.json()).query.search;
  return Promise.all(pages.map(async p => {
    const pr = await fetch(`https://en.wikipedia.org/w/api.php?action=query&prop=extracts|info&exintro=1&explaintext=1&inprop=url&pageids=${p.pageid}&format=json`);
    const page = (await pr.json()).query.pages[p.pageid];
    return { title: page.title, text: (page.extract||'').substring(0,300)+'...', url: page.fullurl, source: 'Wikipedia' };
  }));
}
async function fetchGitHub(q) {
  const res = await fetch(`https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&per_page=3`, { headers: { Accept: 'application/vnd.github.v3+json' } });
  const data = await res.json();
  return data.items.map(repo => ({ title: repo.full_name, text: repo.description||'', url: repo.html_url, icon: repo.owner.avatar_url, source: 'GitHub' }));
}
async function fetchStackExchange(q) {
  if (!STACKEXCHANGE_KEY) return [];
  const res = await fetch(`https://api.stackexchange.com/2.3/search/advanced?key=${STACKEXCHANGE_KEY}&site=stackoverflow&q=${encodeURIComponent(q)}&pagesize=3&order=desc&sort=relevance&filter=withbody`);
  return (await res.json()).items.map(q => ({ title: q.title, text: (q.body||'').replace(/<[^>]*>/g,'').substring(0,300)+'...', url: q.link, source: 'StackExchange' }));
}
async function fetchOpenStreetMap(q) {
  const res = await fetch(`https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(q)}&format=json&limit=3`, { headers: { 'User-Agent': 'SkyCitadel/1.0' } });
  return (await res.json()).map(place => ({ title: place.display_name, text: `Тип: ${place.type}`, url: `https://www.openstreetmap.org/?mlat=${place.lat}&mlon=${place.lon}`, source: 'OpenStreetMap' }));
}
async function fetchOpenLibrary(q) {
  const res = await fetch(`https://openlibrary.org/search.json?q=${encodeURIComponent(q)}&limit=3`);
  return (await res.json()).docs.slice(0,3).map(book => ({ title: book.title, text: book.author_name?.join(', '), url: `https://openlibrary.org${book.key}`, source: 'OpenLibrary' }));
}
async function fetchQuote(q) {
  const tag = q.split(' ')[0].toLowerCase().replace(/[^a-z]/g, '');
  const res = await fetch(`https://api.quotable.io/quotes/random?tags=${tag}&limit=2`);
  return (await res.json()).map(q => ({ title: `Цитата от ${q.author}`, text: `"${q.content}"`, url: `https://quotable.io/quotes/${q._id}`, source: 'Quotes' }));
}
async function fetchNews(q) {
  if (!NEWSAPI_KEY) return [];
  const res = await fetch(`https://newsapi.org/v2/everything?q=${encodeURIComponent(q)}&apiKey=${NEWSAPI_KEY}&pageSize=3&language=ru`);
  return (await res.json()).articles.map(a => ({ title: a.title, text: a.description, url: a.url, icon: a.urlToImage, source: 'News' }));
}
async function fetchCocktail(q) {
  const res = await fetch(`https://www.thecocktaildb.com/api/json/v1/1/search.php?s=${encodeURIComponent(q)}`);
  const data = await res.json();
  if (!data.drinks) return [];
  return data.drinks.slice(0,3).map(d => ({ title: d.strDrink, text: (d.strInstructions||'').substring(0,200)+'...', url: `https://www.thecocktaildb.com/drink/${d.idDrink}`, icon: d.strDrinkThumb, source: 'Cocktails' }));
}

// ---------- Durable Object (мессенджер) ----------
export class SkyChatDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = new Map();
  }
  async fetch(request) {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.state.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }
  async webSocketMessage(ws, msg) {
    const data = JSON.parse(msg);
    switch (data.type) {
      case 'auth': {
        const user = await kvGet('chat_users', data.login);
        if (!user) return ws.send(JSON.stringify({ type:'error', message:'User not found' }));
        this.sessions.set(data.login, ws);
        ws.send(JSON.stringify({ type:'auth_ok', ...user, login: data.login }));
        await this.sendChatList(data.login);
        break;
      }
      case 'get_chats': await this.sendChatList(data.login); break;
      case 'get_messages': await this.handleGetMessages(ws, data.login, data.chatId); break;
      case 'send_message': await this.handleSendMessage(data.login, data.chatId, data.text, null); break;
      case 'file_message': await this.handleSendMessage(data.login, data.chatId, data.text, data.file); break;
      case 'search_user': {
        const all = (await kvList('chat_users')).filter(u => u !== data.login && u.toLowerCase().includes((data.query||'').toLowerCase()));
        ws.send(JSON.stringify({ type:'user_search_result', users: all.map(u => ({ login: u })) }));
        break;
      }
      case 'create_private_chat': await this.createPrivateChat(data.login, data.target); break;
      case 'create_group': await this.createGroup(data.login, data.name); break;
      case 'create_channel': await this.createChannel(data.login, data.name); break;
      case 'join_group': await this.joinGroup(data.login, data.chatId); break;
      case 'leave_group': await this.leaveGroup(data.login, data.chatId); break;
      case 'delete_chat': await this.deleteChat(data.login, data.chatId); break;
      case 'block_chat': await this.blockChat(data.login, data.chatId); break;
      case 'unblock_chat': await this.unblockChat(data.login, data.chatId); break;
      case 'call_offer': case 'call_answer': case 'ice_candidate': case 'call_end':
        await this.forwardSignaling(data, data.login); break;
    }
  }
  webSocketClose(ws) { for (const [l, s] of this.sessions) { if (s === ws) this.sessions.delete(l); } }

  async sendChatList(user) {
    const ids = await kvList('chats');
    const list = {};
    for (const id of ids) {
      const chat = await kvGet('chats', id);
      if (!chat || chat.hidden?.includes(user)) continue;
      if (!chat.members.includes(user)) continue;
      let name = chat.name;
      if (chat.type === 'private') name = chat.members.find(m => m !== user) || chat.name;
      list[id] = { id, type: chat.type, name, lastMsg: chat.messages?.slice(-1)[0]?.text?.slice(0,30) || '', blocked: chat.blocked?.includes(user) || false };
    }
    this.sessions.get(user)?.send(JSON.stringify({ type:'chat_list', chats: list }));
  }

  async handleGetMessages(ws, user, chatId) {
    const chat = await kvGet('chats', chatId);
    if (!chat || !chat.members.includes(user)) return ws.send(JSON.stringify({ type:'messages', messages: [] }));
    ws.send(JSON.stringify({ type:'messages', messages: chat.messages || [] }));
  }

  async handleSendMessage(user, chatId, text, file) {
    const chat = await kvGet('chats', chatId);
    if (!chat || !chat.members.includes(user)) return;
    const message = { from: user, text: text || '', time: Date.now() };
    if (file) message.file = { name: file.name, type: file.type, data: file.url || file.data, size: file.size };
    chat.messages = chat.messages || [];
    chat.messages.push(message);
    await kvPut('chats', chatId, chat);
    for (const m of chat.members) {
      if (m !== user && this.sessions.has(m) && !chat.blocked?.includes(m)) {
        this.sessions.get(m).send(JSON.stringify({ type:'message', chatId, ...message }));
      }
    }
  }

  async createPrivateChat(u1, u2) {
    const id = [u1, u2].sort().join('_');
    if (!await kvGet('chats', id)) await kvPut('chats', id, { type:'private', members:[u1,u2], messages:[], created: Date.now() });
    await this.sendChatList(u1); await this.sendChatList(u2);
    this.sessions.get(u1)?.send(JSON.stringify({ type:'chat_created', chatId: id }));
  }

  async createGroup(user, name) {
    const id = 'group_' + Date.now();
    await kvPut('chats', id, { type:'group', name, members:[user], messages:[], created: Date.now() });
    await this.sendChatList(user);
  }

  async createChannel(user, name) {
    const id = 'channel_' + Date.now();
    await kvPut('chats', id, { type:'channel', name, members:[user], messages:[], created: Date.now() });
    await this.sendChatList(user);
  }

  async joinGroup(user, chatId) {
    const chat = await kvGet('chats', chatId);
    if (!chat || (chat.type !== 'group' && chat.type !== 'channel')) return;
    if (!chat.members.includes(user)) { chat.members.push(user); await kvPut('chats', chatId, chat); }
    await this.sendChatList(user);
  }

  async leaveGroup(user, chatId) {
    const chat = await kvGet('chats', chatId);
    if (!chat || (chat.type !== 'group' && chat.type !== 'channel')) return;
    chat.members = chat.members.filter(m => m !== user);
    await kvPut('chats', chatId, chat);
    await this.sendChatList(user);
  }

  async deleteChat(user, chatId) {
    const chat = await kvGet('chats', chatId);
    if (!chat) return;
    if (chat.type === 'private') {
      if (!chat.hidden) chat.hidden = [];
      if (!chat.hidden.includes(user)) chat.hidden.push(user);
      await kvPut('chats', chatId, chat);
    } else if ((chat.type === 'group' || chat.type === 'channel') && chat.members[0] === user) {
      await kvDelete('chats', chatId);
    }
    await this.sendChatList(user);
  }

  async blockChat(user, chatId) {
    const chat = await kvGet('chats', chatId);
    if (!chat) return;
    if (!chat.blocked) chat.blocked = [];
    if (!chat.blocked.includes(user)) chat.blocked.push(user);
    await kvPut('chats', chatId, chat);
    await this.sendChatList(user);
  }

  async unblockChat(user, chatId) {
    const chat = await kvGet('chats', chatId);
    if (!chat) return;
    if (chat.blocked) chat.blocked = chat.blocked.filter(m => m !== user);
    await kvPut('chats', chatId, chat);
    await this.sendChatList(user);
  }

  async forwardSignaling(msg, from) {
    const chat = await kvGet('chats', msg.chatId);
    if (!chat) return;
    const other = chat.members.find(m => m !== from);
    if (other && this.sessions.has(other)) {
      this.sessions.get(other).send(JSON.stringify({ ...msg, from }));
    }
  }
}

// ---------- Основной обработчик ----------
export default {
  async fetch(request, env, ctx) {
    globalThis.SKYCITADEL_KV = env.SKYCITADEL_KV;
    globalThis.SPOTIFY_CLIENT_ID = env.SPOTIFY_CLIENT_ID;
    globalThis.SPOTIFY_CLIENT_SECRET = env.SPOTIFY_CLIENT_SECRET;
    globalThis.NEWSAPI_KEY = env.NEWSAPI_KEY;
    globalThis.STACKEXCHANGE_KEY = env.STACKEXCHANGE_KEY;

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // WebSocket
    if (path.startsWith('/ws')) {
      const durableObjectId = env.SKYCHAT_DO.idFromName('global');
      const durableObject = env.SKYCHAT_DO.get(durableObjectId);
      return durableObject.fetch(request);
    }

    // REST
    try {
      switch (true) {
        case path === '/healthix': return Response.json({ status:'ok' });
        case path === '/register': return await handleRegister(request);
        case path === '/login': return await handleLogin(request);
        case path === '/me': return await handleMe(request);
        case path === '/chat/register': return await handleChatRegister(request);
        case path === '/chat/login_salt': return await handleChatLoginSalt(request);
        case path === '/api/weather': return await handleWeather(request);
        case path === '/announcements': return method === 'GET' ? await getAnnouncements() : await postAnnouncement(request);
        case path === '/search_groups': return await searchGroups(request);
        case path === '/get_upload_token': return Response.json({ token: crypto.randomUUID() });
        case path === '/upload_file': return await uploadFile(request);
        case path.startsWith('/files/'): return env.SKYCITADEL_KV.get(path.replace('/files/', ''), 'arrayBuffer').then(r => new Response(r));
        case path === '/spotify/token': return await spotifyToken(request);
        case path === '/spotify/save-token': return await spotifySaveToken(request);
        case path === '/spotify/get-token': return await spotifyGetToken(request);
        case path === '/posts': return method === 'GET' ? await getPosts(request) : await createPost(request);
        case path.startsWith('/posts/') && path.endsWith('/like'): return await likePost(request, path);
        case path.startsWith('/posts/') && path.endsWith('/comments'): return await comments(request, path);
        case path.startsWith('/admin/ban'): return await banUser(request);
        case path === '/api/search': return await search(request);
        default: return new Response('Not found', { status: 404 });
      }
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), { status: 500 });
    }
  }
};
