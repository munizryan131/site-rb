'use strict';
// RB Manutenções Elétricas - servidor do site (sem dependências externas)
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILE = path.join(DATA_DIR, 'data.json');
const PUB = path.join(__dirname, 'public');
const HOURS = [18, 19, 20, 21], DAY = 864e5;
fs.mkdirSync(DATA_DIR, { recursive: true });

let db = { slots: {}, users: [], sessions: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(FILE, 'utf8'))); } catch (e) {}
function save() { const t = FILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(db)); fs.renameSync(t, FILE); }
const uid = () => crypto.randomBytes(8).toString('hex');
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function hashPw(pw, salt) { salt = salt || crypto.randomBytes(16).toString('hex'); return { salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') }; }
function checkPw(u, pw) { const h = crypto.scryptSync(pw, u.salt, 64), b = Buffer.from(u.hash, 'hex'); return b.length === h.length && crypto.timingSafeEqual(h, b); }
const pub = u => ({ id: u.id, user: u.user, name: u.name, role: u.role });

// Administrador inicial definido por variáveis de ambiente
const AU = (process.env.ADMIN_USER || '').trim().toLowerCase(), AP = process.env.ADMIN_PASSWORD || '';
if (AU && AP.length >= 8) {
  let u = db.users.find(x => x.user === AU);
  if (!u) { db.users.push({ id: uid(), user: AU, name: process.env.ADMIN_NAME || 'Renato Bueno', role: 'admin', ...hashPw(AP) }); save(); }
  else if (process.env.ADMIN_RESET === '1') { Object.assign(u, hashPw(AP), { role: 'admin' }); save(); }
}
if (!db.users.length) console.log('ATENCAO: defina ADMIN_USER e ADMIN_PASSWORD (min. 8 caracteres) para criar o primeiro acesso.');

const fails = new Map();
function limited(k) { const f = fails.get(k); return f && f.n >= 8 && Date.now() - f.t < 15 * 60e3; }
function fail(k) { const f = fails.get(k); if (f && Date.now() - f.t < 15 * 60e3) f.n++; else fails.set(k, { n: 1, t: Date.now() }); }

function cookie(req, n) { const m = (req.headers.cookie || '').split(/;\s*/).find(c => c.startsWith(n + '=')); return m ? m.slice(n.length + 1) : null; }
function getUser(req) {
  const t = cookie(req, 'rb_session'); if (!t) return null;
  const s = db.sessions[sha(t)]; if (!s || s.exp < Date.now()) return null;
  return db.users.find(u => u.id === s.uid) || null;
}
function setCookie(req, res, v, age) {
  const sec = (req.headers['x-forwarded-proto'] || '').split(',')[0] === 'https' || req.socket.encrypted;
  res.setHeader('Set-Cookie', `rb_session=${v}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}` + (sec ? '; Secure' : ''));
}
function dropSessions(id) { for (const k of Object.keys(db.sessions)) if (db.sessions[k].uid === id) delete db.sessions[k]; }

function json(res, code, o) { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(o)); }
function body(req) {
  return new Promise((ok, no) => {
    let d = '', n = 0;
    req.on('data', c => { n += c.length; if (n > 2e6) { no(new Error('grande')); req.destroy(); } else d += c; });
    req.on('end', () => { try { ok(d ? JSON.parse(d) : {}); } catch (e) { no(new Error('JSON inválido')); } });
  });
}
function cleanSlots(s) {
  if (!s || typeof s !== 'object' || Array.isArray(s)) return null;
  const out = {}, keys = Object.keys(s); if (keys.length > 2000) return null;
  for (const k of keys) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(k) || !s[k] || typeof s[k] !== 'object') return null;
    const o = {};
    for (const h of Object.keys(s[k])) { if (!HOURS.includes(+h) || !['wait', 'busy'].includes(s[k][h])) return null; o[h] = s[k][h]; }
    if (Object.keys(o).length) out[k] = o;
  }
  return out;
}
const str = (v, max) => typeof v === 'string' ? v.trim().slice(0, max) : '';
const ip = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

async function route(req, res, p) {
  const m = req.method, user = getUser(req);
  if (m === 'GET') {
    if (p === '/api/agenda') return json(res, 200, { slots: db.slots, setup: db.users.length === 0 });
    if (p === '/api/me') return json(res, 200, { user: user ? pub(user) : null });
    if (p === '/api/users') { if (!user || user.role !== 'admin') return json(res, 403, { error: 'Sem permissão' }); return json(res, 200, { users: db.users.map(pub) }); }
    if (p === '/api/backup') { if (!user || user.role !== 'admin') return json(res, 403, { error: 'Sem permissão' }); return json(res, 200, { slots: db.slots, users: db.users }); }
    return json(res, 404, { error: 'Não encontrado' });
  }
  if (m !== 'POST') return json(res, 405, { error: 'Método não permitido' });
  if (!/application\/json/.test(req.headers['content-type'] || '')) return json(res, 415, { error: 'Requisição inválida' });
  let b; try { b = await body(req); } catch (e) { return json(res, 400, { error: e.message }); }

  if (p === '/api/login') {
    const name = str(b.user, 60).toLowerCase(), k = ip(req) + '|' + name;
    if (limited(k) || limited(ip(req))) return json(res, 429, { error: 'Muitas tentativas. Aguarde 15 minutos.' });
    const u = db.users.find(x => x.user === name);
    if (!u || typeof b.password !== 'string' || !checkPw(u, b.password)) { fail(k); fail(ip(req)); return json(res, 401, { error: 'Usuário ou senha incorretos.' }); }
    fails.delete(k);
    const t = crypto.randomBytes(32).toString('hex');
    for (const x of Object.keys(db.sessions)) if (db.sessions[x].exp < Date.now()) delete db.sessions[x];
    db.sessions[sha(t)] = { uid: u.id, exp: Date.now() + 30 * DAY }; save();
    setCookie(req, res, t, 30 * 86400);
    return json(res, 200, { user: pub(u) });
  }
  if (p === '/api/logout') {
    const t = cookie(req, 'rb_session'); if (t) { delete db.sessions[sha(t)]; save(); }
    setCookie(req, res, '', 0); return json(res, 200, { ok: true });
  }
  if (!user) return json(res, 401, { error: 'Entre na sua conta para continuar.' });

  if (p === '/api/agenda') {
    const date = str(b.date, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !b.set || typeof b.set !== 'object') return json(res, 400, { error: 'Dados inválidos' });
    const d = Object.assign({}, db.slots[date]);
    for (const h of Object.keys(b.set)) {
      if (!HOURS.includes(+h) || !['free', 'wait', 'busy'].includes(b.set[h])) return json(res, 400, { error: 'Horário inválido' });
      if (b.set[h] === 'free') delete d[h]; else d[h] = b.set[h];
    }
    if (Object.keys(d).length) db.slots[date] = d; else delete db.slots[date];
    save(); return json(res, 200, { ok: true });
  }
  if (p === '/api/password') {
    const nw = typeof b.new === 'string' ? b.new : '';
    if (typeof b.old !== 'string' || !checkPw(user, b.old)) return json(res, 400, { error: 'Senha atual incorreta.' });
    if (nw.length < 8) return json(res, 400, { error: 'A nova senha precisa ter pelo menos 8 caracteres.' });
    Object.assign(user, hashPw(nw)); save(); return json(res, 200, { ok: true });
  }
  if (user.role !== 'admin') return json(res, 403, { error: 'Sem permissão' });
  if (p === '/api/users/add') {
    const name = str(b.name, 60), login = str(b.user, 40).toLowerCase(), pw = typeof b.password === 'string' ? b.password : '';
    if (!name || !/^[a-z0-9._-]{3,40}$/.test(login)) return json(res, 400, { error: 'Informe o nome e um usuário (3 a 40 letras minúsculas, números, ponto, hífen ou _).' });
    if (pw.length < 8) return json(res, 400, { error: 'A senha precisa ter pelo menos 8 caracteres.' });
    if (db.users.some(u => u.user === login)) return json(res, 400, { error: 'Esse usuário já existe.' });
    db.users.push({ id: uid(), user: login, name, role: b.admin ? 'admin' : 'user', ...hashPw(pw) }); save();
    return json(res, 200, { ok: true });
  }
  if (p === '/api/users/delete') {
    const t = db.users.find(u => u.id === b.id);
    if (!t) return json(res, 404, { error: 'Usuário não encontrado' });
    if (t.id === user.id) return json(res, 400, { error: 'Você não pode remover a si mesmo.' });
    db.users = db.users.filter(u => u.id !== t.id); dropSessions(t.id); save(); return json(res, 200, { ok: true });
  }
  if (p === '/api/users/password') {
    const t = db.users.find(u => u.id === b.id), pw = typeof b.password === 'string' ? b.password : '';
    if (!t) return json(res, 404, { error: 'Usuário não encontrado' });
    if (pw.length < 8) return json(res, 400, { error: 'A senha precisa ter pelo menos 8 caracteres.' });
    Object.assign(t, hashPw(pw)); if (t.id !== user.id) dropSessions(t.id); save(); return json(res, 200, { ok: true });
  }
  if (p === '/api/restore') {
    const s = cleanSlots(b.slots), us = b.users;
    const okU = Array.isArray(us) && us.length < 200 && us.every(u => u && typeof u.id === 'string' && /^[a-z0-9._-]{3,40}$/.test(u.user) && typeof u.name === 'string' && ['admin', 'user'].includes(u.role) && /^[0-9a-f]+$/.test(u.salt || '') && /^[0-9a-f]+$/.test(u.hash || '')) && us.some(u => u.role === 'admin');
    if (!s || !okU) return json(res, 400, { error: 'Arquivo de backup inválido.' });
    db.slots = s; db.users = us.map(u => ({ id: u.id, user: u.user, name: u.name.slice(0, 60), role: u.role, salt: u.salt, hash: u.hash }));
    for (const k of Object.keys(db.sessions)) if (!db.users.some(u => u.id === db.sessions[k].uid)) delete db.sessions[k];
    save(); return json(res, 200, { ok: true });
  }
  return json(res, 404, { error: 'Não encontrado' });
}

const TYPES = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.txt': 'text/plain' };
function serveStatic(p, res) {
  let f = path.normalize(decodeURIComponent(p)).replace(/^(\.\.[\/\\])+/, '');
  if (f === path.sep || f === '.' || f === '') f = 'index.html';
  const full = path.join(PUB, f);
  if (!full.startsWith(PUB)) { res.writeHead(403); return res.end(); }
  fs.readFile(full, (e, d) => {
    if (e) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Página não encontrada'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(full)] || 'application/octet-stream', 'Cache-Control': path.extname(full) === '.html' ? 'no-cache' : 'public, max-age=3600' });
    res.end(d);
  });
}
http.createServer(async (req, res) => {
  try {
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    const p = new URL(req.url, 'http://x').pathname;
    if (p.startsWith('/api/')) return await route(req, res, p);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    serveStatic(p, res);
  } catch (e) { console.error(e); if (!res.headersSent) json(res, 500, { error: 'Erro interno' }); }
}).listen(PORT, () => console.log('Site rodando na porta ' + PORT));
