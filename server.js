/**
 * server.js — robust env-driven WebSocket + Firebase RTDB + FCM revive logic
 * Paste this file in project root. Use .env recommended format (see README above).
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const WebSocket = require('ws');
const admin = require('firebase-admin');

const PORT = parseInt(process.env.PORT || '8080', 10);
const HTTP_PORT = parseInt(process.env.HTTP_PORT || String(PORT + 1), 10);
const DATABASE_URL = process.env.DATABASE_URL || '';
const SERVICE_ACCOUNT_PATH = process.env.SERVICE_ACCOUNT_PATH || '';
const FIREBASE_CONFIG_ENV = process.env.FIREBASE_CONFIG || '';
const FIREBASE_CONFIG_BASE64 = process.env.FIREBASE_CONFIG_BASE64 || '';

const PING_INTERVAL_MS = parseInt(process.env.PING_INTERVAL_MS || '3000', 10);
const ACTIVE_WINDOW_MS = parseInt(process.env.ACTIVE_WINDOW_MS || String(30 * 1000), 10);
const PAUSE_MS = parseInt(process.env.PAUSE_MS || String(3 * 60 * 1000), 10);
const OFFLINE_AGG_MS = parseInt(process.env.OFFLINE_AGG_MS || '2000', 10);
const ANDROID_TTL_MS = parseInt(process.env.ANDROID_TTL_MS || String(60 * 60 * 1000), 10);
const MAX_CYCLES = parseInt(process.env.MAX_CYCLES || '0', 10); // 0 = infinite

function log(...a) { console.log(new Date().toISOString(), ...a); }
function warn(...a) { console.warn(new Date().toISOString(), ...a); }
function errlog(...a) { console.error(new Date().toISOString(), ...a); }

function maskToken(t) {
  if (!t || typeof t !== 'string') return '<null>';
  if (t.length <= 10) return t;
  return `${t.slice(0,4)}...${t.slice(-6)}`;
}

function tryParseJson(str) {
  if (!str || typeof str !== 'string') return null;
  try { return JSON.parse(str); } catch (e) { return null; }
}

/* -------------------- PRIVATE KEY NORMALIZATION -------------------- */

function stripQuotes(s){
  if (!s || typeof s !== 'string') return s;
  s = s.trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1,-1);
  }
  return s;
}

function normalizePrivateKey(raw){
  if (!raw || typeof raw !== 'string') return null;
  let s = raw;

  s = stripQuotes(s);

  // handle double-escaped backslashes like "\\n" -> "\n" then -> actual newline
  s = s.replace(/\\\\n/g, '\\n');

  // convert escaped newlines to real newlines
  s = s.replace(/\\n/g, '\n');

  // normalize CRLF
  s = s.replace(/\r\n/g, '\n');

  // trim and ensure trailing newline
  s = s.trim() + '\n';

  // if the PEM is collapsed into a single line (no newline chars inside),
  // try to rewrap the body into 64-char lines.
  if (s.indexOf('\n') === -1 || (!s.includes('-----BEGIN PRIVATE KEY-----') && s.includes('BEGIN PRIVATE KEY'))) {
    // best-effort: try inserting header/footer
    const header = '-----BEGIN PRIVATE KEY-----';
    const footer = '-----END PRIVATE KEY-----';
    const body = s.replace(/(-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\\n|\n)/g,'').trim();
    if (body.length > 0) {
      const wrapped = body.match(/.{1,64}/g).join('\n');
      s = header + '\n' + wrapped + '\n' + footer + '\n';
    }
  }

  // ensure header and footer lines
  s = s.replace(/\s*-----BEGIN PRIVATE KEY-----\s*/s, '-----BEGIN PRIVATE KEY-----\n');
  s = s.replace(/\s*-----END PRIVATE KEY-----\s*/s, '\n-----END PRIVATE KEY-----\n');
  s = s.replace(/\n{2,}/g, '\n'); // collapse multiple blank lines

  return s;
}

function looksLikePem(s){
  if (!s || typeof s !== 'string') return false;
  const re = /^-----BEGIN PRIVATE KEY-----\n([A-Za-z0-9+\/=\n]+)\n-----END PRIVATE KEY-----\n?$/s;
  return re.test(s);
}

/* -------------------- load service account (multiple fallbacks) -------------------- */

function extractFirebaseConfigFromDotEnv(){
  try {
    const envPath = path.join(process.cwd(), '.env');
    if (!fs.existsSync(envPath)) return null;
    const raw = fs.readFileSync(envPath, 'utf8');
    const key = 'FIREBASE_CONFIG';
    const idx = raw.indexOf(key + '=');
    if (idx === -1) return null;
    let i = idx + (key + '=').length;
    while (i < raw.length && (raw[i] === ' ' || raw[i] === '\t')) i++;
    const firstBrace = raw.indexOf('{', i);
    if (firstBrace === -1) return null;
    let depth = 0, j = firstBrace, found = -1;
    for (; j < raw.length; j++) {
      const ch = raw[j];
      if (ch === '{') depth++;
      else if (ch === '}') { depth--; if (depth === 0) { found = j; break; } }
    }
    if (found === -1) return null;
    const jsonText = raw.slice(firstBrace, found + 1);
    return tryParseJson(jsonText) || tryParseJson(jsonText.replace(/\r?\n/g,'\\n')) || null;
  } catch (e) {
    log('[env-extract] error', e && e.message);
    return null;
  }
}

let SERVICE_ACCOUNT = null;

// 1) Prefer explicit FIREBASE_* env fields
(function tryFromFields(){
  const type = process.env.FIREBASE_TYPE || process.env.TYPE;
  const project_id = process.env.FIREBASE_PROJECT_ID || process.env.PROJECT_ID;
  const raw_key = process.env.FIREBASE_PRIVATE_KEY || process.env.PRIVATE_KEY;
  const client_email = process.env.FIREBASE_CLIENT_EMAIL || process.env.CLIENT_EMAIL;
  if (project_id && raw_key && client_email) {
    const pk = normalizePrivateKey(raw_key);
    SERVICE_ACCOUNT = {
      type: type || 'service_account',
      project_id,
      private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID || process.env.PRIVATE_KEY_ID,
      private_key: pk,
      client_email,
      client_id: process.env.FIREBASE_CLIENT_ID || process.env.CLIENT_ID,
      auth_uri: process.env.FIREBASE_AUTH_URI || process.env.AUTH_URI || 'https://accounts.google.com/o/oauth2/auth',
      token_uri: process.env.FIREBASE_TOKEN_URI || process.env.TOKEN_URI || 'https://oauth2.googleapis.com/token',
      auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL || process.env.AUTH_PROVIDER_X509_CERT_URL || 'https://www.googleapis.com/oauth2/v1/certs',
      client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL || process.env.CLIENT_X509_CERT_URL
    };
    log('[init] service account assembled from FIREBASE_* env fields');
  }
})();

// 2) FIREBASE_CONFIG JSON string
if (!SERVICE_ACCOUNT && FIREBASE_CONFIG_ENV) {
  const parsed = tryParseJson(FIREBASE_CONFIG_ENV) || tryParseJson(FIREBASE_CONFIG_ENV.replace(/\r?\n/g,'\\n'));
  if (parsed) {
    if (parsed.private_key) parsed.private_key = normalizePrivateKey(parsed.private_key);
    SERVICE_ACCOUNT = parsed;
    log('[init] loaded service account from FIREBASE_CONFIG env');
  } else {
    log('[init] FIREBASE_CONFIG present but could not parse JSON');
  }
}

// 3) FIREBASE_CONFIG_BASE64
if (!SERVICE_ACCOUNT && FIREBASE_CONFIG_BASE64) {
  try {
    const raw = Buffer.from(FIREBASE_CONFIG_BASE64, 'base64').toString('utf8');
    const parsed = tryParseJson(raw) || tryParseJson(raw.replace(/\r?\n/g,'\\n'));
    if (parsed) {
      if (parsed.private_key) parsed.private_key = normalizePrivateKey(parsed.private_key);
      SERVICE_ACCOUNT = parsed;
      log('[init] loaded service account from FIREBASE_CONFIG_BASE64');
    } else log('[init] FIREBASE_CONFIG_BASE64 present but not parseable');
  } catch (e) { warn('[init] FIREBASE_CONFIG_BASE64 decode failed', e && e.message); }
}

// 4) SERVICE_ACCOUNT_PATH
if (!SERVICE_ACCOUNT && SERVICE_ACCOUNT_PATH) {
  try {
    const saPath = path.isAbsolute(SERVICE_ACCOUNT_PATH) ? SERVICE_ACCOUNT_PATH : path.join(process.cwd(), SERVICE_ACCOUNT_PATH);
    if (fs.existsSync(saPath)) {
      const required = require(saPath);
      if (required && required.private_key) required.private_key = normalizePrivateKey(required.private_key);
      SERVICE_ACCOUNT = required;
      log('[init] loaded service account from SERVICE_ACCOUNT_PATH:', saPath);
    } else log('[init] SERVICE_ACCOUNT_PATH set but file missing at', saPath);
  } catch (e) { warn('[init] require SERVICE_ACCOUNT_PATH failed', e && e.message); }
}

// 5) Scan raw .env for FIREBASE_CONFIG block
if (!SERVICE_ACCOUNT) {
  const parsed = extractFirebaseConfigFromDotEnv();
  if (parsed) {
    if (parsed.private_key) parsed.private_key = normalizePrivateKey(parsed.private_key);
    SERVICE_ACCOUNT = parsed;
    log('[init] loaded service account by scanning .env (multiline support)');
  } else {
    log('[init] No FIREBASE_CONFIG parsed from .env scan');
  }
}

if (!SERVICE_ACCOUNT) {
  errlog('[init] Could not load service account. Provide one of: FIREBASE_* env fields, FIREBASE_CONFIG, FIREBASE_CONFIG_BASE64 or SERVICE_ACCOUNT_PATH');
  process.exit(1);
}

if (!DATABASE_URL) {
  errlog('[init] DATABASE_URL is required in .env (your RTDB URL).');
  process.exit(1);
}

// debug preview for key (do not print entire key)
if (SERVICE_ACCOUNT.private_key) {
  const preview = SERVICE_ACCOUNT.private_key.slice(0,120).replace(/\n/g,'\\n');
  log('[init] private_key preview (first 120 chars, \\n shown):', preview + (SERVICE_ACCOUNT.private_key.length>120 ? '...' : ''));
  log('[init] quick pem check ->', looksLikePem(SERVICE_ACCOUNT.private_key) ? 'ok' : 'failed (will still try init)');
} else warn('[init] no private_key present in resolved service account');

try {
  admin.initializeApp({
    credential: admin.credential.cert(SERVICE_ACCOUNT),
    databaseURL: DATABASE_URL
  });
  log('[init] firebase-admin initialized for project:', SERVICE_ACCOUNT.project_id || '(unknown)');
} catch (e) {
  errlog('[init] firebase-admin initialization failed:');
  if (e && e.stack) errlog(e.stack);
  else errlog(e && e.message ? e.message : e);
  process.exit(1);
}

/* -------------------- rest of server logic -------------------- */

const db = admin.database();
const statusRef = db.ref('status');
const tokensRef = db.ref('fcmTokens');

const clients = new Map();
const wsBySocket = new Map();
const jobs = new Map();

async function getFcmTokenForDevice(deviceId) {
  try {
    const snap = await tokensRef.child(deviceId).once('value');
    if (!snap.exists()) { log('[token-read]', deviceId, '=> no token'); return null; }
    const val = snap.val();
    const token = (typeof val === 'string') ? val : (val && val.token) ? val.token : null;
    if (token) log('[token-read]', deviceId, '=>', maskToken(token)); else log('[token-read]', deviceId, '=> token node exists but empty');
    return token;
  } catch (err) { errlog('[fcm] token read error', deviceId, err && err.message); return null; }
}

function buildFcmMessage(token, deviceId, attempt) {
  return {
    token,
    android: { priority: 'high', collapseKey: `server_offline_ping_${deviceId}`, ttl: ANDROID_TTL_MS },
    data: { type: 'server_offline_ping', deviceId: String(deviceId), attempt: String(attempt), ts: String(Date.now()) }
  };
}

async function sendFcm(token, deviceId, attempt) {
  const msg = buildFcmMessage(token, deviceId, attempt);
  log('[fcm-send] attempting -> device=', deviceId, 'token=', maskToken(token), 'attempt=', attempt);
  try {
    const res = await admin.messaging().send(msg);
    log('[fcm-send] SUCCESS ->', res);
    return { ok: true, res };
  } catch (err) {
    const code = (err && (err.code || (err.errorInfo && err.errorInfo.code))) || (err && err.message) || 'unknown';
    errlog('[fcm-send] ERROR -> device=', deviceId, 'code=', code);
    return { ok: false, err, code };
  }
}

function stopJobFor(deviceId) {
  const j = jobs.get(deviceId);
  if (!j) { log('[job-stop] no job for', deviceId); return; }
  j.stopped = true;
  if (j.activeInterval) clearInterval(j.activeInterval);
  if (j.pauseTimeout) clearTimeout(j.pauseTimeout);
  jobs.delete(deviceId);
  log('[job] stopped', deviceId);
}

async function startJobFor(deviceId, statusVal = {}) {
  if (jobs.has(deviceId)) { log('[job] already running for', deviceId); return; }
  let token = statusVal.fcmToken || null;
  if (!token) token = await getFcmTokenForDevice(deviceId);
  if (!token) { log('[job] NO TOKEN -> skipping revive job for', deviceId); return; }
  log('[job] starting revive job for', deviceId, 'token=', maskToken(token));
  let cycleCount = 0;
  const job = { deviceId, token, activeInterval: null, pauseTimeout: null, stopped: false };
  jobs.set(deviceId, job);

  const runActiveWindow = async () => {
    if (job.stopped) return;
    cycleCount += 1;
    let attempts = 0;
    const myCycle = cycleCount;
    log('[job] active window start', deviceId, 'cycle', myCycle);

    attempts += 1;
    const s0 = await sendFcm(job.token, deviceId, `${myCycle}-${attempts}`);
    if (!s0.ok) {
      const c0 = s0.code || (s0.err && s0.err.code);
      if (c0 === 'messaging/registration-token-not-registered' || c0 === 'messaging/invalid-registration-token') {
        warn('[job] token invalid -> removing from DB and stopping job for', deviceId);
        try { await tokensRef.child(deviceId).remove(); log('[db] removed invalid token for', deviceId); } catch (e) { warn('[db] remove failed', e && e.message); }
        stopJobFor(deviceId); return;
      }
    }

    const start = Date.now();
    job.activeInterval = setInterval(async () => {
      if (job.stopped) { clearInterval(job.activeInterval); job.activeInterval = null; return; }
      try {
        const snap = await statusRef.child(deviceId).once('value');
        const val = snap.val() || {};
        if (val.online) { log('[job] device came online -> stopping job for', deviceId); stopJobFor(deviceId); return; }
      } catch (e) { errlog('[job] status read err', deviceId, e && e.message); }

      if (Date.now() - start >= ACTIVE_WINDOW_MS) {
        clearInterval(job.activeInterval); job.activeInterval = null;
        log('[job] active window ended for', deviceId);
        schedulePauseAndRepeat(); return;
      }

      attempts += 1;
      const sent = await sendFcm(job.token, deviceId, `${myCycle}-${attempts}`);
      if (!sent.ok) {
        const c = sent.code || (sent.err && sent.err.code);
        if (c === 'messaging/registration-token-not-registered' || c === 'messaging/invalid-registration-token') {
          warn('[job] invalid token -> removing and stopping job', deviceId);
          try { await tokensRef.child(deviceId).remove(); log('[db] removed invalid token for', deviceId); } catch (e) { warn('[db] remove failed', e && e.message); }
          stopJobFor(deviceId); return;
        } else warn('[job] non-token error while sending FCM', deviceId, c);
      }
    }, PING_INTERVAL_MS);
  };

  const schedulePauseAndRepeat = () => {
    if (MAX_CYCLES > 0 && cycleCount >= MAX_CYCLES) { log('[job] MAX_CYCLES reached -> stop', deviceId); stopJobFor(deviceId); return; }
    log('[job] pausing', PAUSE_MS, 'ms for', deviceId);
    job.pauseTimeout = setTimeout(async () => {
      try {
        const snap = await statusRef.child(deviceId).once('value');
        if (snap.exists() && snap.val().online) { log('[job] device became online -> stop', deviceId); stopJobFor(deviceId); return; }
        runActiveWindow().catch(e => { errlog('[job] runActiveWindow err', e && e.message); stopJobFor(deviceId); });
      } catch (e) { errlog('[job] check err', e && e.message); runActiveWindow().catch(() => stopJobFor(deviceId)); }
    }, PAUSE_MS);
  };

  const offlineSince = Date.now() - (statusVal.timestamp || 0);
  if (offlineSince < OFFLINE_AGG_MS) {
    const wait = OFFLINE_AGG_MS - offlineSince;
    log('[job] aggregating for', wait, 'ms before starting', deviceId);
    job.pauseTimeout = setTimeout(() => { runActiveWindow().catch(e => { errlog('[job] initial run err', e && e.message); stopJobFor(deviceId); }); }, wait);
  } else runActiveWindow().catch(e => { errlog('[job] initial run err', e && e.message); stopJobFor(deviceId); });
}

/* -------------------- WebSocket server -------------------- */

const wss = new WebSocket.Server({ port: PORT }, () => log('[ws] listening on', PORT));

wss.on('connection', (ws, req) => {
  const remote = (req && req.socket && req.socket.remoteAddress) ? req.socket.remoteAddress : 'unknown';
  log('[ws] client connected from', remote);

  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', async (data) => {
    let msg;
    try { msg = JSON.parse(data.toString()); } catch (e) { warn('[ws] invalid JSON from', remote); return; }

    if (msg.type === 'register' && msg.deviceId) {
      const deviceId = String(msg.deviceId);
      const fcmToken = msg.fcmToken || null;

      if (fcmToken) {
        try {
          await tokensRef.child(deviceId).set({ token: fcmToken, updatedAt: admin.database.ServerValue.TIMESTAMP });
          log('[db] stored token for', deviceId, maskToken(fcmToken));
        } catch (e) { warn('[db] failed to store token for', deviceId, e && e.message); }
      } else log('[ws-register] no fcmToken provided by client', deviceId);

      clients.set(deviceId, ws);
      wsBySocket.set(ws, deviceId);

      try {
        await statusRef.child(deviceId).set({ online: true, timestamp: admin.database.ServerValue.TIMESTAMP, uniqueid: deviceId });
        log('[db] wrote status online for', deviceId);
      } catch (e) { warn('[db] write status failed', deviceId, e && e.message); }

      try { ws.send(JSON.stringify({ type: 'registered', deviceId, ts: Date.now() })); } catch (e) { warn('[ws] send ack failed', deviceId, e && e.message); }

      if (jobs.has(deviceId)) { log('[ws] device returned online -> stopping revive job for', deviceId); stopJobFor(deviceId); }
      return;
    }
  });

  ws.on('close', async (code, reason) => {
    log('[ws] close from', remote, 'code=', code, 'reason=', reason);
    const deviceId = wsBySocket.get(ws);
    if (deviceId) {
      clients.delete(deviceId);
      wsBySocket.delete(ws);
      try {
        await statusRef.child(deviceId).set({ online: false, timestamp: admin.database.ServerValue.TIMESTAMP, uniqueid: deviceId });
        log('[db] wrote status offline for', deviceId);
      } catch (e) { warn('[db] write offline failed', deviceId, e && e.message); }

      try {
        const snap = await statusRef.child(deviceId).once('value');
        const val = snap.val() || {};
        log('[ws] starting revive job after close for', deviceId, 'status=', { online: val.online, timestamp: val.timestamp });
        const token = await getFcmTokenForDevice(deviceId);
        startJobFor(deviceId, { timestamp: val.timestamp || Date.now(), fcmToken: token }).catch(e => errlog('[job] start err', e && e.message));
      } catch (e) { errlog('[job] after-close start err', e && e.message); }
    } else log('[ws] close for unknown ws (not registered)');
  });

  ws.on('error', (err) => { warn('[ws] error from', remote, err && err.message ? err.message : err); });
});

const healthInterval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) { try { ws.terminate(); } catch (e) {} ; return; }
    ws.isAlive = false;
    try { ws.ping(); } catch (e) {}
  });
}, 30000);

/* -------------------- HTTP admin API -------------------- */
const app = express();
app.use(bodyParser.json());
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));
app.get('/connected', (req, res) => { const keys = Array.from(clients.keys()); log('[http] /connected ->', keys.length); res.json({ connected: keys }); });
app.post('/trigger-revive', async (req, res) => {
  const deviceId = req.body.deviceId; if (!deviceId) return res.status(400).json({ error: 'deviceId required' });
  try { const snap = await statusRef.child(deviceId).once('value'); const val = snap.val() || {}; log('[http] trigger-revive for', deviceId); await startJobFor(deviceId, { timestamp: val.timestamp || 0, fcmToken: await getFcmTokenForDevice(deviceId) }); return res.json({ started: true }); }
  catch (e) { errlog('[http] trigger-revive error', e && e.message); return res.status(500).json({ error: String(e) }); }
});
app.post('/stop-revive', (req, res) => { const deviceId = req.body.deviceId; if (!deviceId) return res.status(400).json({ error: 'deviceId required' }); stopJobFor(deviceId); return res.json({ stopped: true }); });
const httpServer = app.listen(HTTP_PORT, () => log('[http] admin API running on', HTTP_PORT));

process.on('SIGINT', () => {
  log('[shutdown] SIGINT, cleaning up');
  healthInterval && clearInterval(healthInterval);
  try { httpServer.close(); } catch (e) {}
  try { wss.close(); } catch (e) {}
  for (const k of Array.from(jobs.keys())) stopJobFor(k);
  process.exit(0);
});

log('[init] started. DB=', DATABASE_URL, 'WS port=', PORT, 'HTTP port=', HTTP_PORT);