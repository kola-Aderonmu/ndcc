'use strict';
/* Defence Cyber Command website: zero-dependency Node.js server (Node 18+).
   Serves /public, a JSON API, protected CMS endpoints and file uploads. */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'public');
const UP = path.join(DATA, 'uploads');
const DBF = path.join(DATA, 'db.json');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const COLS = ['posts', 'gallery', 'people', 'jobs', 'resources'];
const SITE_KEYS = ['heroTitle', 'heroText', 'heroVideo', 'heroImage', 'threat', 'pollQ', 'pollOpts', 'aboutImage', 'email', 'phone', 'address'];
const URL_KEYS = ['image', 'file', 'heroVideo', 'heroImage', 'aboutImage'];
const MAX_UPLOAD = 20 * 1024 * 1024;

fs.mkdirSync(UP, { recursive: true });

/* ---------- storage ---------- */
let db = { posts: {}, gallery: {}, people: {}, jobs: {}, resources: {}, site: {}, votes: {}, incidents: [], user: null };
try { db = { ...db, ...JSON.parse(fs.readFileSync(DBF, 'utf8')) }; } catch (e) { /* first run */ }
function save() {
  const tmp = DBF + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DBF);
}

/* ---------- passwords & sessions ---------- */
function hashPw(p, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(p, salt, 64).toString('hex') };
}
function checkPw(p, u) {
  const h = crypto.scryptSync(p, u.salt, 64), b = Buffer.from(u.hash, 'hex');
  return h.length === b.length && crypto.timingSafeEqual(h, b);
}
if (!db.user) {
  const envPw = process.env.ADMIN_PASS;
  db.user = { name: process.env.ADMIN_USER || 'dccadmin', ...hashPw(envPw || 'Dcc@Admin2026'), mustChange: !envPw };
  save();
  if (!envPw) console.log('[setup] Default CMS login created: dccadmin / Dcc@Admin2026 (you must change it on first sign-in)');
}
const sessions = new Map(); // token -> expiry
const SESSION_MS = 8 * 3600 * 1000;
function newSession() { const t = crypto.randomBytes(32).toString('hex'); sessions.set(t, Date.now() + SESSION_MS); return t; }
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(c => { const i = c.indexOf('='); if (i > 0) o[c.slice(0, i).trim()] = c.slice(i + 1).trim(); });
  return o;
}
function authed(req) {
  const t = cookies(req).dcc_sid, e = t && sessions.get(t);
  if (!e) return false;
  if (e < Date.now()) { sessions.delete(t); return false; }
  return true;
}

/* ---------- rate limiting ---------- */
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now(), a = (hits.get(key) || []).filter(t => now - t < windowMs);
  if (a.length >= max) { hits.set(key, a); return true; }
  return false;
}
function hit(key, windowMs) { const now = Date.now(); const a = (hits.get(key) || []).filter(t => now - t < windowMs); a.push(now); hits.set(key, a); }
setInterval(() => { const now = Date.now(); for (const [k, a] of hits) { const f = a.filter(t => now - t < 3600e3); f.length ? hits.set(k, f) : hits.delete(k); } for (const [t, e] of sessions) if (e < now) sessions.delete(t); }, 600e3).unref();
function ip(req) {
  if (TRUST_PROXY) { const x = (req.headers['x-forwarded-for'] || '').split(',')[0].trim(); if (x) return x; }
  return req.socket.remoteAddress || 'x';
}

/* ---------- helpers ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.ico': 'image/x-icon', '.mp4': 'video/mp4', '.webm': 'video/webm', '.pdf': 'application/pdf', '.txt': 'text/plain; charset=utf-8', '.csv': 'text/csv; charset=utf-8' };
const UPLOAD_TYPES = { // extension -> magic-byte check
  png: b => b.slice(0, 4).toString('hex') === '89504e47',
  jpg: b => b.slice(0, 3).toString('hex') === 'ffd8ff',
  jpeg: b => b.slice(0, 3).toString('hex') === 'ffd8ff',
  gif: b => b.slice(0, 4).toString() === 'GIF8',
  webp: b => b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP',
  mp4: b => b.slice(4, 8).toString() === 'ftyp',
  webm: b => b.slice(0, 4).toString('hex') === '1a45dfa3',
  pdf: b => b.slice(0, 4).toString() === '%PDF',
  doc: b => b.slice(0, 4).toString('hex') === 'd0cf11e0', xls: b => b.slice(0, 4).toString('hex') === 'd0cf11e0', ppt: b => b.slice(0, 4).toString('hex') === 'd0cf11e0',
  docx: b => b.slice(0, 2).toString() === 'PK', xlsx: b => b.slice(0, 2).toString() === 'PK', pptx: b => b.slice(0, 2).toString() === 'PK', zip: b => b.slice(0, 2).toString() === 'PK',
  txt: () => true, csv: () => true
};
const INLINE = new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'webm', 'pdf']);

function secHeaders(res, req) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data: https:; media-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  if (req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}
function json(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); }
function body(req, max = 1e6) {
  return new Promise((ok, no) => {
    const ch = []; let n = 0;
    req.on('data', c => { n += c.length; if (n > max) { no(Object.assign(new Error('too_large'), { code: 'too_large' })); req.destroy(); } else ch.push(c); });
    req.on('end', () => ok(Buffer.concat(ch)));
    req.on('error', no);
  });
}
async function jbody(req) { try { return JSON.parse((await body(req)).toString() || '{}'); } catch (e) { throw Object.assign(new Error('bad_json'), { code: 'bad_json' }); } }
function cookieFlags(req) { return 'HttpOnly; SameSite=Strict; Path=/' + (req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted ? '; Secure' : ''); }

function cleanDoc(d, keys) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return null;
  const o = {};
  for (const [k, v] of Object.entries(d)) {
    if (!/^[A-Za-z0-9_]{1,30}$/.test(k) || k === '__proto__' || (keys && !keys.includes(k))) continue;
    if (typeof v === 'string') {
      if (v.length > 20000) return null;
      if (URL_KEYS.includes(k) && v && !/^(\/uploads\/[a-f0-9]{32}\.[a-z0-9]{2,4}|https:\/\/[^\s"'<>]+)$/.test(v)) return null;
      o[k] = v;
    } else if (typeof v === 'number' && isFinite(v)) o[k] = v;
    else if (typeof v === 'boolean') o[k] = v;
  }
  return o;
}
function publicData(req) {
  const list = c => Object.entries(db[c]).map(([id, d]) => ({ id, ...d }));
  const counts = []; Object.values(db.votes).forEach(i => { if (Number.isInteger(i) && i >= 0 && i < 20) counts[i] = (counts[i] || 0) + 1; });
  for (let i = 0; i < counts.length; i++) counts[i] = counts[i] || 0;
  const vid = cookies(req).dcc_vid;
  return { posts: list('posts'), gallery: list('gallery'), people: list('people'), jobs: list('jobs'), resources: list('resources'), site: db.site, votes: { counts, mine: vid && vid in db.votes ? db.votes[vid] : null } };
}

/* ---------- API ---------- */
async function api(req, res, url) {
  const m = req.method, p = url.pathname, who = ip(req);
  if (m !== 'GET' && req.headers['x-requested-with'] !== 'dcc') return json(res, 403, { error: 'forbidden' });

  if (m === 'GET' && p === '/api/data') return json(res, 200, publicData(req));
  if (m === 'GET' && p === '/api/me') return json(res, 200, { auth: authed(req), mustChange: authed(req) && !!db.user.mustChange });

  if (m === 'POST' && p === '/api/login') {
    if (limited('login:' + who, 5, 15 * 60e3)) return json(res, 429, { error: 'locked' });
    const b = await jbody(req);
    const okUser = typeof b.u === 'string' && typeof b.p === 'string' && b.u === db.user.name && checkPw(b.p, db.user);
    if (!okUser) { hit('login:' + who, 15 * 60e3); return json(res, 401, { error: 'invalid' }); }
    const t = newSession();
    res.setHeader('Set-Cookie', `dcc_sid=${t}; Max-Age=${SESSION_MS / 1000}; ${cookieFlags(req)}`);
    return json(res, 200, { ok: true, mustChange: !!db.user.mustChange });
  }
  if (m === 'POST' && p === '/api/logout') {
    const t = cookies(req).dcc_sid; if (t) sessions.delete(t);
    res.setHeader('Set-Cookie', `dcc_sid=; Max-Age=0; ${cookieFlags(req)}`);
    return json(res, 200, { ok: true });
  }

  if (m === 'POST' && p === '/api/vote') {
    if (limited('vote:' + who, 20, 3600e3)) return json(res, 429, { error: 'rate_limited' });
    const b = await jbody(req);
    if (!Number.isInteger(b.c) || b.c < 0 || b.c >= 20) return json(res, 400, { error: 'invalid' });
    let vid = cookies(req).dcc_vid;
    if (!vid || !/^[a-f0-9]{32}$/.test(vid)) { vid = crypto.randomBytes(16).toString('hex'); res.setHeader('Set-Cookie', `dcc_vid=${vid}; Max-Age=31536000; ${cookieFlags(req)}`); }
    hit('vote:' + who, 3600e3);
    if (!(vid in db.votes)) { db.votes[vid] = b.c; save(); }
    return json(res, 200, { votes: publicData({ headers: { cookie: 'dcc_vid=' + vid } }).votes });
  }

  if (m === 'POST' && p === '/api/incident') {
    if (limited('inc:' + who, 5, 3600e3)) return json(res, 429, { error: 'rate_limited' });
    const b = await jbody(req);
    const s = (v, n) => String(v ?? '').trim().slice(0, n);
    const details = s(b.details, 5000);
    if (details.length < 10) return json(res, 400, { error: 'invalid' });
    hit('inc:' + who, 3600e3);
    db.incidents.unshift({ id: crypto.randomBytes(8).toString('hex'), ts: new Date().toISOString(), name: s(b.name, 120), email: s(b.email, 200), details });
    db.incidents = db.incidents.slice(0, 1000);
    save();
    return json(res, 200, { ok: true });
  }

  /* ----- everything below needs a session ----- */
  if (!authed(req)) return json(res, 401, { error: 'unauthorized' });

  if (m === 'POST' && p === '/api/password') {
    const b = await jbody(req);
    if (typeof b.cp !== 'string' || !checkPw(b.cp, db.user)) return json(res, 400, { error: 'bad_current' });
    if (typeof b.u !== 'string' || b.u.length < 4 || b.u.length > 60 || typeof b.p !== 'string' || b.p.length < 10 || b.p.length > 200) return json(res, 400, { error: 'weak' });
    db.user = { name: b.u, ...hashPw(b.p), mustChange: false };
    sessions.clear(); const t = newSession();
    res.setHeader('Set-Cookie', `dcc_sid=${t}; Max-Age=${SESSION_MS / 1000}; ${cookieFlags(req)}`);
    save();
    return json(res, 200, { ok: true });
  }
  if (m === 'GET' && p === '/api/incidents') return json(res, 200, { items: db.incidents });

  if (db.user.mustChange) return json(res, 403, { error: 'change_password' });

  if (m === 'DELETE' && /^\/api\/incident\/[a-f0-9]{16}$/.test(p)) { const id = p.split('/').pop(); db.incidents = db.incidents.filter(i => i.id !== id); save(); return json(res, 200, { ok: true }); }

  let mm = p.match(/^\/api\/c\/([a-z]+)\/([A-Za-z0-9_-]{1,40})$/);
  if (mm) {
    const [, col, id] = mm;
    if (col === 'settings' && id === 'site') {
      if (m !== 'PUT') return json(res, 405, { error: 'method' });
      const d = cleanDoc(await jbody(req), SITE_KEYS); if (!d) return json(res, 400, { error: 'invalid' });
      db.site = d; save(); return json(res, 200, { ok: true });
    }
    if (!COLS.includes(col)) return json(res, 404, { error: 'not_found' });
    if (m === 'PUT') { const d = cleanDoc(await jbody(req)); if (!d) return json(res, 400, { error: 'invalid' }); db[col][id] = d; save(); return json(res, 200, { ok: true }); }
    if (m === 'DELETE') { delete db[col][id]; save(); return json(res, 200, { ok: true }); }
    return json(res, 405, { error: 'method' });
  }

  if (m === 'POST' && p === '/api/upload') {
    let name = ''; try { name = decodeURIComponent(req.headers['x-filename'] || ''); } catch (e) { /* ignore */ }
    const ext = path.extname(name).slice(1).toLowerCase();
    if (!UPLOAD_TYPES[ext]) return json(res, 415, { error: 'type_not_allowed' });
    const buf = await body(req, MAX_UPLOAD);
    if (!buf.length || !UPLOAD_TYPES[ext](buf)) return json(res, 415, { error: 'bad_file' });
    const fn = crypto.randomBytes(16).toString('hex') + '.' + ext;
    fs.writeFileSync(path.join(UP, fn), buf);
    return json(res, 200, { url: '/uploads/' + fn });
  }
  return json(res, 404, { error: 'not_found' });
}

/* ---------- static files ---------- */
function serve(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  let rel; try { rel = decodeURIComponent(url.pathname); } catch (e) { res.writeHead(400); return res.end(); }
  if (rel.includes('\0')) { res.writeHead(400); return res.end(); }
  let file, upload = false;
  if (rel.startsWith('/uploads/')) { file = path.join(UP, path.basename(rel)); upload = true; }
  else { file = path.join(PUB, rel === '/' ? 'index.html' : rel); if (!file.startsWith(PUB + path.sep)) { res.writeHead(403); return res.end(); } }
  fs.stat(file, (e, st) => {
    if (e || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    const ext = path.extname(file).toLowerCase(), h = { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Content-Length': st.size };
    if (upload) { h['Content-Security-Policy'] = "default-src 'none'; sandbox"; if (!INLINE.has(ext.slice(1))) h['Content-Disposition'] = 'attachment'; h['Cache-Control'] = 'public, max-age=86400'; }
    else h['Cache-Control'] = ext === '.html' ? 'no-cache' : 'public, max-age=3600';
    res.writeHead(200, h);
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

const server = http.createServer(async (req, res) => {
  secHeaders(res, req);
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    serve(req, res, url);
  } catch (e) {
    if (e.code === 'too_large') return json(res, 413, { error: 'too_large' });
    if (e.code === 'bad_json') return json(res, 400, { error: 'bad_json' });
    console.error(e);
    if (!res.headersSent) json(res, 500, { error: 'server_error' });
  }
});
if (require.main === module) server.listen(PORT, () => console.log(`DCC site running on http://localhost:${PORT}`));
module.exports = server;
