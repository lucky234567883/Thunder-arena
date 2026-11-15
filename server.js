'use strict';
/*
 * Thunder Arena 3D — сервер друзей (Node.js, без внешних зависимостей).
 * Запуск:  node server.js        (нужен Node.js 16+)
 * Игра отдаётся с этого же сервера: положи файл игры рядом как index.html.
 */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const GAME_FILE = process.env.GAME_FILE || path.join(__dirname, 'index.html');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';      // =1 если сервер за прокси (Render, Railway, nginx)
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || '*';     // можно ограничить адресом сайта с игрой
// Хранение в GitHub Gist (для хостингов, где диск стирается, например бесплатный Render).
// Данные шифруются (AES-256-GCM) ключом из DATA_SECRET, поэтому в Gist лежит нечитаемый текст.
const GIST_ID = process.env.GIST_ID || '', GH_TOKEN = process.env.GITHUB_TOKEN || '', DATA_SECRET = process.env.DATA_SECRET || '';
const GH_API = (process.env.GITHUB_API || 'https://api.github.com').replace(/\/+$/, '');
const GIST_FILE = 'thunder-data.txt';
const REMOTE = !!(GIST_ID && GH_TOKEN);
if (REMOTE && DATA_SECRET.length < 8) { console.error('Для хранения в Gist задай DATA_SECRET (любой пароль от 8 символов)'); process.exit(1); }
const ONLINE_MS = 60 * 1000;                              // «в сети», если был отклик не раньше минуты назад
const TOKEN_TTL = 60 * 86400 * 1000;
const CLAN_MAX = 30, MAX_CLANS = 1000;
const MAX_FRIENDS = 100, MAX_PENDING = 50, MAX_BODY = 200 * 1024, MAX_AV = 70 * 1024;

// ---------- хранилище (один JSON-файл) ----------
let db = { users: {}, tokens: {}, chats: {}, clans: {} };
try { db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); db.users = db.users || {}; db.tokens = db.tokens || {}; db.chats = db.chats || {}; db.clans = db.clans || {}; } catch (e) { /* первый запуск */ }
let saveTimer = null;
function writeNow() {
  const tmp = DATA_FILE + '.tmp';
  try { fs.writeFileSync(tmp, JSON.stringify(db)); fs.renameSync(tmp, DATA_FILE); } catch (e) { if (!REMOTE) console.error('Ошибка сохранения:', e.message); }
  dirtyRemote = true;
}

// ---------- хранение в Gist ----------
let dirtyRemote = false, pushing = false;
const KEY = REMOTE ? crypto.scryptSync(DATA_SECRET, 'thunder-arena-v1', 32) : null;
function enc(str) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([c.update(str, 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function dec(b64) {
  const b = Buffer.from(b64, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', KEY, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8');
}
async function gh(method, url, body) {
  const r = await fetch(url, { method, headers: Object.assign({ Authorization: 'Bearer ' + GH_TOKEN, 'User-Agent': 'thunder-arena-server', Accept: 'application/vnd.github+json' }, body ? { 'Content-Type': 'application/json' } : {}), body: body ? JSON.stringify(body) : undefined });
  if (!r.ok) throw new Error('GitHub ответил ' + r.status);
  return r;
}
async function loadRemote() {
  const g = await (await gh('GET', GH_API + '/gists/' + GIST_ID)).json();
  const f = g.files && g.files[GIST_FILE];
  if (!f) return null;
  let txt = f.content;
  if (f.truncated || txt == null) txt = await (await gh('GET', f.raw_url)).text();
  txt = String(txt).trim();
  if (txt.length < 40) return null; // заглушка вроде «new» при создании Gist — данных ещё нет
  return JSON.parse(dec(txt));
}
async function pushRemote() {
  if (!REMOTE || !dirtyRemote || pushing) return;
  pushing = true; dirtyRemote = false;
  try { await gh('PATCH', GH_API + '/gists/' + GIST_ID, { files: { [GIST_FILE]: { content: enc(JSON.stringify(db)) } } }); }
  catch (e) { dirtyRemote = true; console.error('Gist: не удалось сохранить —', e.message); }
  pushing = false;
}
setInterval(pushRemote, 15000).unref();
function save() { if (saveTimer) return; saveTimer = setTimeout(() => { saveTimer = null; writeNow(); }, 400); }
async function flushAndExit() {
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  writeNow();
  const t = setTimeout(() => process.exit(0), 8000);
  try { while (pushing) await new Promise(r => setTimeout(r, 100)); await pushRemote(); } catch (e) { /* ignore */ }
  clearTimeout(t); process.exit(0);
}
process.on('SIGINT', flushAndExit); process.on('SIGTERM', flushAndExit);

// ---------- утилиты ----------
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const hashPw = (p, salt) => crypto.scryptSync(p, salt, 32).toString('hex');
const checkPw = (p, u) => { try { return crypto.timingSafeEqual(Buffer.from(hashPw(p, u.salt), 'hex'), Buffer.from(u.hash, 'hex')); } catch (e) { return false; } };
const cleanNick = s => String(s || '').replace(/[<>&"'`\u0000-\u001f]/g, '').trim().slice(0, 16);
const okLogin = l => typeof l === 'string' && /^[a-z0-9_]{3,16}$/.test(l);
const rm = (a, x) => { const i = a.indexOf(x); if (i >= 0) a.splice(i, 1); };
class HttpErr extends Error { constructor(code, msg) { super(msg); this.code = code; } }

// простой ограничитель частоты запросов по IP
const hits = new Map();
function limited(ip, key, max, winMs) {
  const k = key + '|' + ip, now = Date.now();
  let h = hits.get(k);
  if (!h || h.reset < now) { h = { n: 0, reset: now + winMs }; hits.set(k, h); }
  return ++h.n > max;
}
setInterval(() => { const now = Date.now(); for (const [k, h] of hits) if (h.reset < now) hits.delete(k); }, 60000).unref();
setInterval(() => { const now = Date.now(); let ch = false; for (const k in db.tokens) if (now - db.tokens[k].t > TOKEN_TTL) { delete db.tokens[k]; ch = true; } if (ch) save(); }, 3600000).unref();

const msgRate = new Map();
const chatKey = (a, b) => [a, b].sort().join('|');
function unreadFrom(me, f) {
  const c = db.chats[chatKey(me, f)]; if (!c) return 0;
  const r = (db.users[me].read || {})[f] || 0; let n = 0;
  for (const m of c.msgs) if (m.from === f && m.id > r) n++;
  return n;
}

// ---------- кланы ----------
const clanOf = l => { const u = db.users[l]; return u && u.clan && db.clans[u.clan] ? db.clans[u.clan] : null; };
const clanName = s => String(s || '').replace(/[<>&"'`\u0000-\u001f]/g, '').replace(/\s+/g, ' ').trim().slice(0, 20);
const clanTag = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 4);
function clanState(login) {
  const c = clanOf(login); if (!c) return null;
  const now = Date.now(), u = db.users[login], r = u.cread || 0;
  let unread = 0; for (const m of c.chat.msgs) if (m.from !== login && m.id > r) unread++;
  return {
    id: c.id, name: c.name, tag: c.tag, desc: c.desc, leader: c.leader, max: CLAN_MAX, unread,
    members: c.members.filter(l => db.users[l]).map(l => { const s = db.users[l].seen || {}, ago = s.t ? now - s.t : -1; return { login: l, nick: db.users[l].nick, on: !!(s.on && ago >= 0 && ago < ONLINE_MS), ago, leader: l === c.leader }; }),
    reqs: c.leader === login ? c.reqs.filter(l => db.users[l]).map(l => ({ login: l, nick: db.users[l].nick })) : []
  };
}
function dropClan(c) {
  for (const l of c.members) { const u = db.users[l]; if (u) { delete u.clan; delete u.cread; } }
  for (const l of c.reqs) { const u = db.users[l]; if (u) delete u.creq; }
  delete db.clans[c.id];
}
function removeFromClan(login) { // выход/исключение/удаление аккаунта
  const u = db.users[login]; if (!u) return;
  const c = u.clan && db.clans[u.clan];
  delete u.clan; delete u.cread;
  if (u.creq && db.clans[u.creq]) rm(db.clans[u.creq].reqs, login);
  delete u.creq;
  if (!c) return;
  rm(c.members, login);
  if (!c.members.length) { delete db.clans[c.id]; return; }
  if (c.leader === login) c.leader = c.members[0]; // лидерство переходит к самому старому участнику
}
function needClan(a) { const c = clanOf(a.login); if (!c) throw new HttpErr(403, 'Ты не в клане'); return c; }
function needLeader(a) { const c = needClan(a); if (c.leader !== a.login) throw new HttpErr(403, 'Это может только лидер клана'); return c; }
// ---------- лобби для совместной игры (хранятся в памяти) ----------
const LOBBY_MAX = 4, LOBBY_MODES = ['waves', 'cap', 'hold', 'escort'];
const LOBBY_MAPS = ['steppe', 'desert', 'afghan', 'taiga', 'city', 'jungle', 'alps', 'canyon', 'swamp', 'odesa', 'normandy'];
const lobbies = new Map(), lobbyOfUser = new Map(), lobbyInv = new Map();
const lobbyOf = l => { const id = lobbyOfUser.get(l); return (id && lobbies.get(id)) || null; };
const cleanVeh = s => String(s || '').replace(/[<>&"'`\u0000-\u001f]/g, '').trim().slice(0, 30);
function makeLobbyCode() { const al = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let c; do { c = ''; for (let i = 0; i < 5; i++) c += al[crypto.randomInt(al.length)]; } while (lobbies.has(c)); return c; }
function lobbyState(login) {
  const L = lobbyOf(login); if (!L) return null; const now = Date.now();
  return { code: L.id, leader: L.leader, mode: L.mode, map: L.map, startId: L.startId, max: LOBBY_MAX,
    members: L.members.map(m => { const u = db.users[m.login] || {}, s = u.seen || {}, ago = s.t ? now - s.t : -1;
      return { login: m.login, nick: u.nick || m.login, tag: (clanOf(m.login) || {}).tag || '', ready: !!m.ready, veh: m.veh || '', on: !!(s.on && ago >= 0 && ago < ONLINE_MS), leader: m.login === L.leader }; }) };
}
function lobbyInvites(login) {
  const now = Date.now(), list = (lobbyInv.get(login) || []).filter(i => now - i.t < 300000 && lobbies.has(i.code) && lobbies.get(i.code).members.some(m => m.login === i.from));
  lobbyInv.set(login, list);
  if (lobbyOf(login)) return [];
  return list.map(i => { const L = lobbies.get(i.code); return { code: i.code, from: { login: i.from, nick: (db.users[i.from] || {}).nick || i.from }, mode: L.mode, map: L.map, n: L.members.length, max: LOBBY_MAX }; }).filter(i => i.n < LOBBY_MAX);
}
function leaveLobby(login) {
  const L = lobbyOf(login); lobbyOfUser.delete(login); if (!L) return;
  L.members = L.members.filter(m => m.login !== login);
  if (!L.members.length) { lobbies.delete(L.id); return; }
  if (L.leader === login) L.leader = L.members[0].login;
}
setInterval(() => { // убрать из лобби тех, кто пропал больше чем на 3 минуты
  const now = Date.now();
  for (const L of [...lobbies.values()]) for (const m of [...L.members]) { const u = db.users[m.login], t = u && u.seen && u.seen.t; if (!u || !t || now - t > 180000) leaveLobby(m.login); }
}, 60000).unref();
function newToken(login) {
  const tok = crypto.randomBytes(32).toString('hex');
  db.tokens[sha(tok)] = { login, t: Date.now() };
  return tok;
}
function authOf(req, body) {
  let tok = '';
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) tok = h.slice(7);
  else if (body && typeof body.token === 'string') tok = body.token;
  const e = tok && db.tokens[sha(tok)];
  if (!e || Date.now() - e.t > TOKEN_TTL || !db.users[e.login]) throw new HttpErr(401, 'Нужно войти заново');
  return { login: e.login, user: db.users[e.login], tokHash: sha(tok) };
}

// ---------- состояние для клиента ----------
const pub = l => ({ login: l, nick: db.users[l].nick, av: db.users[l].avv || 0, tag: (clanOf(l) || {}).tag || '' });
function state(login) {
  const u = db.users[login], now = Date.now();
  return {
    me: pub(login),
    friends: u.friends.filter(l => db.users[l]).map(l => {
      const s = db.users[l].seen || {}, ago = s.t ? now - s.t : -1;
      return Object.assign(pub(l), { on: !!(s.on && ago >= 0 && ago < ONLINE_MS), ago, unread: unreadFrom(login, l) });
    }),
    incoming: u.inc.filter(l => db.users[l]).map(pub),
    outgoing: u.out.filter(l => db.users[l]).map(pub),
    clan: clanState(login),
    creq: u.creq && db.clans[u.creq] ? { id: u.creq, name: db.clans[u.creq].name, tag: db.clans[u.creq].tag } : null,
    lobby: lobbyState(login),
    linv: lobbyInvites(login)
  };
}
function link(a, b) { // сделать друзьями и убрать заявки
  const A = db.users[a], B = db.users[b];
  for (const [x, y] of [[A, b], [B, a]]) { rm(x.inc, y); rm(x.out, y); if (!x.friends.includes(y)) x.friends.push(y); }
}
function unlink(a, b) {
  const A = db.users[a], B = db.users[b];
  if (!A || !B) return;
  for (const [x, y] of [[A, b], [B, a]]) { rm(x.friends, y); rm(x.inc, y); rm(x.out, y); if (x.read) delete x.read[y]; }
  delete db.chats[chatKey(a, b)]; // переписка удаляется вместе с дружбой
}

// ---------- обработчики API ----------
const routes = {
  'POST /api/register'(req, body, ip) {
    if (limited(ip, 'auth', 20, 600000)) throw new HttpErr(429, 'Слишком много попыток, подожди несколько минут');
    const login = String(body.login || '').trim().toLowerCase(), pass = String(body.pass || ''), nick = cleanNick(body.nick) || login;
    if (!okLogin(login)) throw new HttpErr(400, 'Логин: 3–16 символов, латиница, цифры и _');
    if (pass.length < 4 || pass.length > 100) throw new HttpErr(400, 'Пароль: минимум 4 символа');
    if (db.users[login]) throw new HttpErr(409, 'Такой логин уже занят');
    const salt = crypto.randomBytes(16).toString('hex');
    db.users[login] = { nick, salt, hash: hashPw(pass, salt), created: Date.now(), seen: { t: Date.now(), on: 1 }, friends: [], inc: [], out: [], av: '', avv: 0 };
    const token = newToken(login); save();
    return { token, nick };
  },
  'POST /api/login'(req, body, ip) {
    if (limited(ip, 'auth', 20, 600000)) throw new HttpErr(429, 'Слишком много попыток, подожди несколько минут');
    const login = String(body.login || '').trim().toLowerCase(), u = db.users[login];
    if (!u) throw new HttpErr(404, 'Аккаунта нет на сервере');
    if (!checkPw(String(body.pass || ''), u)) throw new HttpErr(401, 'Неверный пароль');
    const token = newToken(login); u.seen = { t: Date.now(), on: 1 }; save();
    return { token, nick: u.nick };
  },
  'POST /api/logout'(req, body) {
    const a = authOf(req, body); a.user.seen = { t: Date.now(), on: 0 }; delete db.tokens[a.tokHash]; save(); return { ok: true };
  },
  'POST /api/offline'(req, body) { // sendBeacon при закрытии вкладки
    try { const a = authOf(req, body); a.user.seen = { t: Date.now(), on: 0 }; save(); } catch (e) { /* игнорируем */ }
    return { ok: true };
  },
  'POST /api/sync'(req, body) { // «пульс» + актуальные друзья и заявки
    const a = authOf(req, body); a.user.seen = { t: Date.now(), on: body.on === 0 || body.on === false ? 0 : 1 };
    db.tokens[a.tokHash].t = Date.now(); save();
    return state(a.login);
  },
  'POST /api/friends/request'(req, body) {
    const a = authOf(req, body), t = String(body.login || '').trim().toLowerCase();
    if (!okLogin(t)) throw new HttpErr(400, 'Введи логин друга');
    if (t === a.login) throw new HttpErr(400, 'Это твой аккаунт :)');
    const T = db.users[t]; if (!T) throw new HttpErr(404, 'Игрок «' + t + '» не найден на сервере');
    const me = a.user;
    if (me.friends.includes(t)) throw new HttpErr(409, 'Он уже в друзьях');
    if (me.out.includes(t)) throw new HttpErr(409, 'Заявка уже отправлена');
    if (me.inc.includes(t)) { link(a.login, t); save(); return Object.assign(state(a.login), { note: 'Теперь вы друзья с ' + T.nick }); }
    if (me.friends.length >= MAX_FRIENDS) throw new HttpErr(400, 'Достигнут лимит друзей');
    if (me.out.length >= MAX_PENDING || T.inc.length >= MAX_PENDING) throw new HttpErr(400, 'Слишком много заявок');
    me.out.push(t); T.inc.push(a.login); save();
    return Object.assign(state(a.login), { note: 'Заявка отправлена игроку ' + T.nick });
  },
  'POST /api/friends/accept'(req, body) {
    const a = authOf(req, body), t = String(body.login || '').trim().toLowerCase();
    if (!a.user.inc.includes(t) || !db.users[t]) throw new HttpErr(404, 'Заявки нет');
    if (a.user.friends.length >= MAX_FRIENDS) throw new HttpErr(400, 'Достигнут лимит друзей');
    link(a.login, t); save();
    return Object.assign(state(a.login), { note: 'Теперь вы друзья с ' + db.users[t].nick });
  },
  'POST /api/friends/decline'(req, body) {
    const a = authOf(req, body), t = String(body.login || '').trim().toLowerCase();
    rm(a.user.inc, t); if (db.users[t]) rm(db.users[t].out, a.login); save();
    return Object.assign(state(a.login), { note: 'Заявка отклонена' });
  },
  'POST /api/friends/cancel'(req, body) {
    const a = authOf(req, body), t = String(body.login || '').trim().toLowerCase();
    rm(a.user.out, t); if (db.users[t]) rm(db.users[t].inc, a.login); save();
    return Object.assign(state(a.login), { note: 'Заявка отменена' });
  },
  'POST /api/friends/remove'(req, body) {
    const a = authOf(req, body), t = String(body.login || '').trim().toLowerCase();
    unlink(a.login, t); save();
    return Object.assign(state(a.login), { note: 'Удалён из друзей' });
  },
  'POST /api/profile'(req, body) {
    const a = authOf(req, body), n = cleanNick(body.nick);
    if (n.length < 2) throw new HttpErr(400, 'Никнейм: минимум 2 символа');
    a.user.nick = n; save(); return { ok: true, nick: n };
  },
  'POST /api/password'(req, body, ip) {
    if (limited(ip, 'auth', 20, 600000)) throw new HttpErr(429, 'Слишком много попыток, подожди несколько минут');
    const a = authOf(req, body), np = String(body.new || '');
    if (!checkPw(String(body.old || ''), a.user)) throw new HttpErr(401, 'Старый пароль неверный');
    if (np.length < 4 || np.length > 100) throw new HttpErr(400, 'Новый пароль: минимум 4 символа');
    a.user.salt = crypto.randomBytes(16).toString('hex'); a.user.hash = hashPw(np, a.user.salt);
    for (const h in db.tokens) if (db.tokens[h].login === a.login && h !== a.tokHash) delete db.tokens[h]; // выкинуть остальные сессии
    save(); return { ok: true };
  },
  'POST /api/avatar'(req, body) {
    const a = authOf(req, body), d = String(body.data || '');
    if (d === '') { a.user.av = ''; a.user.avv = (a.user.avv || 0) + 1; save(); return { ok: true }; }
    if (d.length > MAX_AV || !/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(d)) throw new HttpErr(400, 'Некорректная картинка (до 70 КБ)');
    a.user.av = d; a.user.avv = (a.user.avv || 0) + 1; save(); return { ok: true, v: a.user.avv };
  },
  'POST /api/avatar/get'(req, body) {
    const a = authOf(req, body), l = String(body.login || '').trim().toLowerCase(), u = db.users[l];
    if (!u) throw new HttpErr(404, 'Нет такого игрока');
    if (l !== a.login && !a.user.friends.includes(l) && !a.user.inc.includes(l) && !a.user.out.includes(l)) throw new HttpErr(403, 'Нет доступа');
    return { data: u.av || '', v: u.avv || 0 };
  },
  'POST /api/recovery/set'(req, body) {
    const a = authOf(req, body), c = String(body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (c.length < 12) throw new HttpErr(400, 'Некорректный код');
    a.user.rs = crypto.randomBytes(16).toString('hex'); a.user.rc = hashPw(c, a.user.rs); save();
    return { ok: true };
  },
  'POST /api/recover'(req, body, ip) { // сброс пароля по коду восстановления
    if (limited(ip, 'auth', 20, 600000)) throw new HttpErr(429, 'Слишком много попыток, подожди несколько минут');
    const login = String(body.login || '').trim().toLowerCase(), c = String(body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, ''), np = String(body.new || '');
    if (limited(login, 'rec', 5, 3600000)) throw new HttpErr(429, 'Слишком много попыток для этого аккаунта, попробуй через час');
    const u = db.users[login];
    let ok = false;
    if (u && u.rc && u.rs && c.length >= 12) { try { ok = crypto.timingSafeEqual(Buffer.from(hashPw(c, u.rs), 'hex'), Buffer.from(u.rc, 'hex')); } catch (e) { ok = false; } }
    if (!ok) throw new HttpErr(403, 'Неверный логин или код');
    if (np.length < 4 || np.length > 100) throw new HttpErr(400, 'Новый пароль: минимум 4 символа');
    u.salt = crypto.randomBytes(16).toString('hex'); u.hash = hashPw(np, u.salt);
    delete u.rc; delete u.rs; // код одноразовый
    for (const h in db.tokens) if (db.tokens[h].login === login) delete db.tokens[h];
    save(); return { ok: true };
  },
  'POST /api/chat/send'(req, body) {
    const a = authOf(req, body), to = String(body.to || '').trim().toLowerCase();
    if (!db.users[to] || !a.user.friends.includes(to)) throw new HttpErr(403, 'Писать можно только друзьям');
    const text = String(body.text || '').replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').trim().slice(0, 300);
    if (!text) throw new HttpErr(400, 'Пустое сообщение');
    const now = Date.now(), r = (msgRate.get(a.login) || []).filter(t => now - t < 30000);
    if (r.length >= 20) throw new HttpErr(429, 'Слишком часто, подожди немного');
    r.push(now); msgRate.set(a.login, r);
    const k = chatKey(a.login, to), c = db.chats[k] || (db.chats[k] = { next: 1, msgs: [] });
    c.msgs.push({ id: c.next++, from: a.login, t: now, text });
    if (c.msgs.length > 100) c.msgs.splice(0, c.msgs.length - 100);
    save(); return { ok: true };
  },
  'POST /api/chat/get'(req, body) {
    const a = authOf(req, body), w = String(body.with || '').trim().toLowerCase(), since = +body.since || 0;
    if (!db.users[w] || !a.user.friends.includes(w)) throw new HttpErr(403, 'Нет доступа');
    const c = db.chats[chatKey(a.login, w)], msgs = c ? c.msgs.filter(m => m.id > since).slice(-100) : [];
    if (body.read && c && c.msgs.length) {
      a.user.read = a.user.read || {}; const last = c.msgs[c.msgs.length - 1].id;
      if ((a.user.read[w] || 0) !== last) { a.user.read[w] = last; save(); }
    }
    return { msgs };
  },
  'POST /api/clan/create'(req, body) {
    const a = authOf(req, body);
    if (a.user.clan && db.clans[a.user.clan]) throw new HttpErr(409, 'Ты уже в клане');
    if (limited(a.login, 'clan', 8, 3600000)) throw new HttpErr(429, 'Слишком много попыток, подожди немного');
    const name = clanName(body.name), tag = clanTag(body.tag), desc = clanName(String(body.desc || '').slice(0, 100)).slice(0, 100);
    if (name.length < 3) throw new HttpErr(400, 'Название клана: минимум 3 символа');
    if (tag.length < 2) throw new HttpErr(400, 'Тег клана: 2–4 символа, латиница и цифры');
    if (Object.keys(db.clans).length >= MAX_CLANS) throw new HttpErr(400, 'Достигнут лимит кланов на сервере');
    for (const id in db.clans) { const c = db.clans[id]; if (c.name.toLowerCase() === name.toLowerCase()) throw new HttpErr(409, 'Клан с таким названием уже есть'); if (c.tag === tag) throw new HttpErr(409, 'Тег «' + tag + '» уже занят'); }
    if (a.user.creq && db.clans[a.user.creq]) rm(db.clans[a.user.creq].reqs, a.login);
    delete a.user.creq;
    const id = crypto.randomBytes(4).toString('hex');
    db.clans[id] = { id, name, tag, desc, leader: a.login, members: [a.login], reqs: [], created: Date.now(), chat: { next: 1, msgs: [] } };
    a.user.clan = id; a.user.cread = 0; save();
    return Object.assign(state(a.login), { note: 'Клан «' + name + '» [' + tag + '] создан' });
  },
  'POST /api/clan/search'(req, body) {
    authOf(req, body);
    const q = String(body.q || '').trim().toLowerCase().slice(0, 30);
    const list = Object.values(db.clans).filter(c => !q || c.name.toLowerCase().includes(q) || c.tag.toLowerCase().includes(q))
      .sort((x, y) => y.members.length - x.members.length).slice(0, 20)
      .map(c => ({ id: c.id, name: c.name, tag: c.tag, desc: c.desc, members: c.members.length, max: CLAN_MAX }));
    return { list };
  },
  'POST /api/clan/join'(req, body) {
    const a = authOf(req, body), c = db.clans[String(body.id || '')];
    if (a.user.clan && db.clans[a.user.clan]) throw new HttpErr(409, 'Ты уже в клане');
    if (!c) throw new HttpErr(404, 'Клан не найден');
    if (a.user.creq && db.clans[a.user.creq]) throw new HttpErr(409, 'Сначала отмени прошлую заявку');
    if (c.members.length >= CLAN_MAX) throw new HttpErr(400, 'В клане нет мест');
    if (c.reqs.length >= 30) throw new HttpErr(400, 'У клана слишком много заявок');
    c.reqs.push(a.login); a.user.creq = c.id; save();
    return Object.assign(state(a.login), { note: 'Заявка в клан [' + c.tag + '] отправлена' });
  },
  'POST /api/clan/cancel'(req, body) {
    const a = authOf(req, body);
    if (a.user.creq && db.clans[a.user.creq]) rm(db.clans[a.user.creq].reqs, a.login);
    delete a.user.creq; save();
    return Object.assign(state(a.login), { note: 'Заявка отменена' });
  },
  'POST /api/clan/accept'(req, body) {
    const a = authOf(req, body), c = needLeader(a), t = String(body.login || '').trim().toLowerCase(), T = db.users[t];
    if (!T || !c.reqs.includes(t)) throw new HttpErr(404, 'Заявки нет');
    if (c.members.length >= CLAN_MAX) throw new HttpErr(400, 'В клане нет мест');
    rm(c.reqs, t); delete T.creq;
    if (T.clan && db.clans[T.clan]) throw new HttpErr(409, 'Игрок уже вступил в другой клан');
    c.members.push(t); T.clan = c.id; T.cread = c.chat.msgs.length ? c.chat.msgs[c.chat.msgs.length - 1].id : 0; save();
    return Object.assign(state(a.login), { note: T.nick + ' принят(а) в клан' });
  },
  'POST /api/clan/decline'(req, body) {
    const a = authOf(req, body), c = needLeader(a), t = String(body.login || '').trim().toLowerCase();
    rm(c.reqs, t); if (db.users[t]) delete db.users[t].creq; save();
    return Object.assign(state(a.login), { note: 'Заявка отклонена' });
  },
  'POST /api/clan/kick'(req, body) {
    const a = authOf(req, body), c = needLeader(a), t = String(body.login || '').trim().toLowerCase();
    if (t === a.login || !c.members.includes(t)) throw new HttpErr(400, 'Нельзя исключить этого игрока');
    removeFromClan(t); save();
    return Object.assign(state(a.login), { note: 'Игрок исключён из клана' });
  },
  'POST /api/clan/leave'(req, body) {
    const a = authOf(req, body); needClan(a); removeFromClan(a.login); save();
    return Object.assign(state(a.login), { note: 'Ты покинул клан' });
  },
  'POST /api/clan/disband'(req, body) {
    const a = authOf(req, body), c = needLeader(a); dropClan(c); save();
    return Object.assign(state(a.login), { note: 'Клан распущен' });
  },
  'POST /api/clan/chat/send'(req, body) {
    const a = authOf(req, body), c = needClan(a);
    const text = String(body.text || '').replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').trim().slice(0, 300);
    if (!text) throw new HttpErr(400, 'Пустое сообщение');
    const now = Date.now(), r = (msgRate.get(a.login) || []).filter(t => now - t < 30000);
    if (r.length >= 20) throw new HttpErr(429, 'Слишком часто, подожди немного');
    r.push(now); msgRate.set(a.login, r);
    c.chat.msgs.push({ id: c.chat.next++, from: a.login, nick: a.user.nick, t: now, text });
    if (c.chat.msgs.length > 100) c.chat.msgs.splice(0, c.chat.msgs.length - 100);
    save(); return { ok: true };
  },
  'POST /api/clan/chat/get'(req, body) {
    const a = authOf(req, body), c = needClan(a), since = +body.since || 0;
    const msgs = c.chat.msgs.filter(m => m.id > since).slice(-100).map(m => Object.assign({}, m, { nick: db.users[m.from] ? db.users[m.from].nick : m.nick }));
    if (body.read && c.chat.msgs.length) { const last = c.chat.msgs[c.chat.msgs.length - 1].id; if ((a.user.cread || 0) !== last) { a.user.cread = last; save(); } }
    return { msgs };
  },
  'POST /api/lobby/create'(req, body) {
    const a = authOf(req, body), mode = String(body.mode || ''), map = String(body.map || '');
    if (lobbyOf(a.login)) throw new HttpErr(409, 'Ты уже в лобби');
    if (!LOBBY_MODES.includes(mode) || !LOBBY_MAPS.includes(map)) throw new HttpErr(400, 'Выбери режим и карту');
    if (limited(a.login, 'lobby', 20, 3600000)) throw new HttpErr(429, 'Слишком много лобби, подожди немного');
    const id = makeLobbyCode();
    lobbies.set(id, { id, leader: a.login, members: [{ login: a.login, ready: false, veh: cleanVeh(body.veh) }], mode, map, startId: 0, created: Date.now() });
    lobbyOfUser.set(a.login, id);
    return Object.assign(state(a.login), { note: 'Лобби создано, код ' + id });
  },
  'POST /api/lobby/invite'(req, body) {
    const a = authOf(req, body), L = lobbyOf(a.login), t = String(body.login || '').trim().toLowerCase();
    if (!L) throw new HttpErr(403, 'Сначала создай лобби');
    if (!db.users[t] || t === a.login) throw new HttpErr(404, 'Игрок не найден');
    const mc = clanOf(a.login), tc = clanOf(t);
    if (!a.user.friends.includes(t) && !(mc && tc && mc.id === tc.id)) throw new HttpErr(403, 'Приглашать можно друзей и одноклановцев');
    if (lobbyOf(t)) throw new HttpErr(409, 'Игрок уже в лобби');
    if (L.members.length >= LOBBY_MAX) throw new HttpErr(400, 'В лобби нет мест');
    if (limited(a.login, 'linv', 30, 3600000)) throw new HttpErr(429, 'Слишком много приглашений');
    const list = (lobbyInv.get(t) || []).filter(i => i.code !== L.id); list.push({ code: L.id, from: a.login, t: Date.now() });
    lobbyInv.set(t, list.slice(-5));
    return Object.assign(state(a.login), { note: 'Приглашение отправлено: ' + db.users[t].nick });
  },
  'POST /api/lobby/join'(req, body) {
    const a = authOf(req, body), code = String(body.code || '').trim().toUpperCase();
    if (limited(a.login, 'ljoin', 20, 600000)) throw new HttpErr(429, 'Слишком много попыток, подожди несколько минут');
    if (lobbyOf(a.login)) throw new HttpErr(409, 'Ты уже в лобби');
    const L = lobbies.get(code); if (!L) throw new HttpErr(404, 'Лобби не найдено (или уже закрыто)');
    if (L.members.length >= LOBBY_MAX) throw new HttpErr(400, 'В лобби нет мест');
    L.members.push({ login: a.login, ready: false, veh: cleanVeh(body.veh) }); lobbyOfUser.set(a.login, code);
    lobbyInv.set(a.login, (lobbyInv.get(a.login) || []).filter(i => i.code !== code));
    return Object.assign(state(a.login), { note: 'Ты в лобби ' + code });
  },
  'POST /api/lobby/decline'(req, body) {
    const a = authOf(req, body), code = String(body.code || '').trim().toUpperCase();
    lobbyInv.set(a.login, (lobbyInv.get(a.login) || []).filter(i => i.code !== code));
    return Object.assign(state(a.login), { note: 'Приглашение отклонено' });
  },
  'POST /api/lobby/ready'(req, body) {
    const a = authOf(req, body), L = lobbyOf(a.login); if (!L) throw new HttpErr(403, 'Ты не в лобби');
    const m = L.members.find(x => x.login === a.login); m.ready = !!body.ready; if (body.veh !== undefined) m.veh = cleanVeh(body.veh);
    return state(a.login);
  },
  'POST /api/lobby/settings'(req, body) {
    const a = authOf(req, body), L = lobbyOf(a.login); if (!L) throw new HttpErr(403, 'Ты не в лобби');
    if (L.leader !== a.login) throw new HttpErr(403, 'Настройки меняет только лидер лобби');
    const mode = String(body.mode || ''), map = String(body.map || '');
    if (!LOBBY_MODES.includes(mode) || !LOBBY_MAPS.includes(map)) throw new HttpErr(400, 'Некорректный режим или карта');
    if (mode !== L.mode || map !== L.map) for (const m of L.members) if (m.login !== L.leader) m.ready = false; // настройки изменились — нужна новая готовность
    L.mode = mode; L.map = map;
    return state(a.login);
  },
  'POST /api/lobby/start'(req, body) {
    const a = authOf(req, body), L = lobbyOf(a.login); if (!L) throw new HttpErr(403, 'Ты не в лобби');
    if (L.leader !== a.login) throw new HttpErr(403, 'Начать бой может только лидер лобби');
    if (L.members.length < 2) throw new HttpErr(400, 'Для совместной игры нужен хотя бы один друг в лобби');
    if (L.members.some(m => m.login !== L.leader && !m.ready)) throw new HttpErr(400, 'Не все игроки готовы');
    L.startId++; for (const m of L.members) if (m.login !== L.leader) m.ready = false;
    return Object.assign(state(a.login), { note: 'Бой начинается!' });
  },
  'POST /api/lobby/leave'(req, body) { const a = authOf(req, body); leaveLobby(a.login); return Object.assign(state(a.login), { note: 'Ты вышел из лобби' }); },
  'POST /api/lobby/kick'(req, body) {
    const a = authOf(req, body), L = lobbyOf(a.login), t = String(body.login || '').trim().toLowerCase();
    if (!L) throw new HttpErr(403, 'Ты не в лобби');
    if (L.leader !== a.login) throw new HttpErr(403, 'Исключать может только лидер');
    if (t === a.login || !L.members.some(m => m.login === t)) throw new HttpErr(400, 'Нельзя исключить этого игрока');
    leaveLobby(t); return Object.assign(state(a.login), { note: 'Игрок исключён из лобби' });
  },
  'POST /api/delete'(req, body, ip) {
    if (limited(ip, 'auth', 20, 600000)) throw new HttpErr(429, 'Слишком много попыток, подожди несколько минут');
    const a = authOf(req, body);
    if (!checkPw(String(body.pass || ''), a.user)) throw new HttpErr(401, 'Пароль неверный');
    for (const l of [...a.user.friends, ...a.user.inc, ...a.user.out]) unlink(a.login, l);
    removeFromClan(a.login); leaveLobby(a.login); lobbyInv.delete(a.login);
    for (const h in db.tokens) if (db.tokens[h].login === a.login) delete db.tokens[h];
    delete db.users[a.login]; save(); return { ok: true };
  }
};

// ---------- HTTP ----------
function send(res, code, obj) {
  const s = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(s);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > MAX_BODY) { reject(new HttpErr(413, 'Слишком большой запрос')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(n ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { reject(new HttpErr(400, 'Некорректный JSON')); } });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOW_ORIGIN);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const ip = (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
  const pathname = (req.url || '/').split('?')[0];

  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    fs.stat(GAME_FILE, (err, st) => {
      if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Положи файл игры рядом с server.js под именем index.html'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': st.size, 'Cache-Control': 'no-cache' });
      fs.createReadStream(GAME_FILE).pipe(res);
    });
    return;
  }
  if (req.method === 'GET' && pathname === '/api/ping') return send(res, 200, { ok: true, name: 'thunder-arena', storage: REMOTE ? 'gist' : 'file', users: Object.keys(db.users).length });

  const handler = routes[req.method + ' ' + pathname];
  if (!handler) return send(res, 404, { error: 'Не найдено' });
  try {
    if (limited(ip, 'api', 300, 60000)) throw new HttpErr(429, 'Слишком много запросов');
    const body = await readBody(req);
    send(res, 200, handler(req, body, ip));
  } catch (e) {
    if (e instanceof HttpErr) send(res, e.code, { error: e.message });
    else { console.error(e); send(res, 500, { error: 'Ошибка сервера' }); }
  }
});
(async () => {
  if (REMOTE) {
    try {
      const r = await loadRemote();
      if (r) { db = r; db.users = db.users || {}; db.tokens = db.tokens || {}; db.chats = db.chats || {}; db.clans = db.clans || {}; console.log('Данные загружены из Gist, игроков: ' + Object.keys(db.users).length); }
      else { console.log('Gist пока пуст — начинаем с чистого листа'); dirtyRemote = true; }
    } catch (e) {
      console.error('Не удалось загрузить данные из Gist (' + e.message + '). Останавливаюсь, чтобы не затереть сохранения. Проверь GIST_ID, GITHUB_TOKEN и DATA_SECRET.');
      process.exit(1);
    }
  }
  server.listen(PORT, () => console.log('Thunder Arena: сервер запущен на порту ' + PORT + '  →  http://localhost:' + PORT + (REMOTE ? '  (данные в Gist)' : '')));
})();
