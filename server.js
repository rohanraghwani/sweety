require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');

const PORT = parseInt(process.env.PORT || '8080', 10);
const DATABASE_URL = process.env.DATABASE_URL || '';
const SERVICE_ACCOUNT_PATH = process.env.SERVICE_ACCOUNT_PATH || '';
const FIREBASE_CONFIG_ENV = process.env.FIREBASE_CONFIG || '';
const FIREBASE_CONFIG_BASE64 = process.env.FIREBASE_CONFIG_BASE64 || '';

const PING_INTERVAL_MS = parseInt(process.env.PING_INTERVAL_MS || '3000', 10);
const ACTIVE_WINDOW_MS = 30000;

function log(...a) { console.log(new Date().toISOString(), ...a); }
function warn(...a) { console.warn(new Date().toISOString(), ...a); }
function errlog(...a) { console.error(new Date().toISOString(), ...a); }

function maskToken(t) { if (!t || typeof t !== 'string') return '<null>'; if (t.length <= 10) return t; return `${t.slice(0,4)}...${t.slice(-6)}`; }
function tryParseJson(str) { if (!str || typeof str !== 'string') return null; try { return JSON.parse(str); } catch { return null; } }
function stripQuotes(s){ if (!s || typeof s !== 'string') return s; s=s.trim(); if((s.startsWith('"')&&s.endsWith('"'))||(s.startsWith("'")&&s.endsWith("'")))s=s.slice(1,-1); return s; }
function normalizePrivateKey(raw){ if (!raw || typeof raw !== 'string') return null; let s=stripQuotes(raw); s=s.replace(/\\\\n/g,'\\n'); s=s.replace(/\\n/g,'\n'); s=s.replace(/\r\n/g,'\n'); s=s.trim()+'\n'; s=s.replace(/\s*-----BEGIN PRIVATE KEY-----\s*/s,'-----BEGIN PRIVATE KEY-----\n'); s=s.replace(/\s*-----END PRIVATE KEY-----\s*/s,'\n-----END PRIVATE KEY-----\n'); s=s.replace(/\n{2,}/g,'\n'); return s; }
function looksLikePem(s){ if (!s||typeof s!=='string') return false; const re=/^-----BEGIN PRIVATE KEY-----\n([A-Za-z0-9+\/=\n]+)\n-----END PRIVATE KEY-----\n?$/s; return re.test(s); }

let SERVICE_ACCOUNT = null;
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

if (!SERVICE_ACCOUNT && FIREBASE_CONFIG_ENV) {
  const parsed = tryParseJson(FIREBASE_CONFIG_ENV) || tryParseJson(FIREBASE_CONFIG_ENV.replace(/\r?\n/g,'\\n'));
  if (parsed) { if (parsed.private_key) parsed.private_key = normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT = parsed; log('[init] loaded from FIREBASE_CONFIG env'); }
}

if (!SERVICE_ACCOUNT && FIREBASE_CONFIG_BASE64) {
  try {
    const raw = Buffer.from(FIREBASE_CONFIG_BASE64, 'base64').toString('utf8');
    const parsed = tryParseJson(raw) || tryParseJson(raw.replace(/\r?\n/g,'\\n'));
    if (parsed) { if (parsed.private_key) parsed.private_key = normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT = parsed; log('[init] loaded from FIREBASE_CONFIG_BASE64'); }
  } catch (e) { warn('[init] FIREBASE_CONFIG_BASE64 decode failed', e && e.message); }
}

if (!SERVICE_ACCOUNT && SERVICE_ACCOUNT_PATH) {
  try {
    const saPath = path.isAbsolute(SERVICE_ACCOUNT_PATH) ? SERVICE_ACCOUNT_PATH : path.join(process.cwd(), SERVICE_ACCOUNT_PATH);
    if (fs.existsSync(saPath)) {
      const required = require(saPath);
      if (required && required.private_key) required.private_key = normalizePrivateKey(required.private_key);
      SERVICE_ACCOUNT = required;
      log('[init] loaded service account from SERVICE_ACCOUNT_PATH:', saPath);
    }
  } catch (e) { warn('[init] require SERVICE_ACCOUNT_PATH failed', e && e.message); }
}

if (!SERVICE_ACCOUNT) {
  errlog('[init] Could not load service account. Provide FIREBASE_* env or file.');
  process.exit(1);
}
if (!DATABASE_URL) {
  errlog('[init] DATABASE_URL is required in .env (your RTDB URL).');
  process.exit(1);
}

if (SERVICE_ACCOUNT.private_key) {
  const preview = SERVICE_ACCOUNT.private_key.slice(0,120).replace(/\n/g,'\\n');
  log('[init] private_key preview (first 120 chars, \\n shown):', preview + (SERVICE_ACCOUNT.private_key.length>120 ? '...' : ''));
  log('[init] quick pem check ->', looksLikePem(SERVICE_ACCOUNT.private_key) ? 'ok' : 'failed');
}

try {
  admin.initializeApp({ credential: admin.credential.cert(SERVICE_ACCOUNT), databaseURL: DATABASE_URL });
  log('[init] firebase-admin initialized for project:', SERVICE_ACCOUNT.project_id || '(unknown)');
} catch (e) {
  errlog('[init] firebase-admin initialization failed:', e.message);
  process.exit(1);
}

// ---- Firebase refs ----
const db = admin.database();
const statusRef = db.ref('status');
const tokensRef = db.ref('fcmTokens');

const jobs = new Map();

// ---- FCM helpers ----
async function getFcmTokenForDevice(deviceId) {
  try {
    const snap = await tokensRef.child(deviceId).once('value');
    if (!snap.exists()) return null;
    const val = snap.val();
    if (typeof val === 'string') return val;
    if (val && val.token) return val.token;
    return null;
  } catch (err) {
    errlog('[fcm] token read error', deviceId, err.message);
    return null;
  }
}

function buildFcmMessage(token, deviceId, attempt, type) {
  return {
    token,
    android: { priority: 'high', ttl: 4000 },
    data: { type, deviceId: String(deviceId), attempt: String(attempt), ts: String(Date.now()) }
  };
}

async function sendFcm(token, deviceId, attempt, type) {
  try {
    const msg = buildFcmMessage(token, deviceId, attempt, type);
    const res = await admin.messaging().send(msg);
    log('[fcm-send] SUCCESS', deviceId, type, res);
    return { ok: true, res };
  } catch (err) {
    errlog('[fcm-send] ERROR', deviceId, type, err.code || err.message);
    return { ok: false, err };
  }
}

// ---- Job logic ----
function stopJobFor(deviceId) {
  const j = jobs.get(deviceId);
  if (!j) return;
  j.stopped = true;
  if (j.activeInterval) clearInterval(j.activeInterval);
  if (j.pauseTimeout) clearTimeout(j.pauseTimeout);
  jobs.delete(deviceId);
  log('[job] stopped', deviceId);
}

async function startJobFor(deviceId, statusVal = {}) {
  if (jobs.has(deviceId)) return;
  let token = statusVal.fcmToken || await getFcmTokenForDevice(deviceId);
  if (!token) return;
  log('[job] starting revive job for', deviceId);

  let cycleCount = 0;
  const job = { deviceId, token, activeInterval: null, pauseTimeout: null, stopped: false };
  jobs.set(deviceId, job);

  const runActiveWindow = async () => {
    if (job.stopped) return;
    cycleCount += 1;
    let attempts = 0;
    const start = Date.now();
    job.activeInterval = setInterval(async () => {
      if (job.stopped) return clearInterval(job.activeInterval);

      try {
        const snap = await statusRef.child(deviceId).once('value');
        const val = snap.val() || {};
        if (val.online) { stopJobFor(deviceId); return; }
      } catch {}

      if (Date.now() - start >= ACTIVE_WINDOW_MS) {
        clearInterval(job.activeInterval);
        job.activeInterval = null;
        schedulePauseAndRepeat();
        return;
      }

      attempts++;
      await sendFcm(job.token, deviceId, `${cycleCount}-${attempts}`, 'server_offline_ping');
    }, PING_INTERVAL_MS);
  };

  const schedulePauseAndRepeat = () => {
    job.pauseTimeout = setTimeout(runActiveWindow, PING_INTERVAL_MS);
  };

  runActiveWindow();
}

// ---- Status watch ----
function handleStatusChange(childKey, val) {
  const online = !!val.online;
  const timestamp = val.timestamp || Date.now();
  if (!online) {
    getFcmTokenForDevice(childKey).then(token => startJobFor(childKey, { timestamp, fcmToken: token }));
  } else {
    if (jobs.has(childKey)) stopJobFor(childKey);
  }
}
statusRef.on('child_added', snap => handleStatusChange(snap.key, snap.val() || {}));
statusRef.on('child_changed', snap => handleStatusChange(snap.key, snap.val() || {}));
statusRef.on('child_removed', snap => { if (jobs.has(snap.key)) stopJobFor(snap.key); });

// ---- Express API ----
const app = express();
app.use(bodyParser.json());

app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

app.post('/sendUpdate', async (req, res) => {
  const deviceId = req.body.deviceId;
  if (!deviceId) return res.status(400).json({ error: 'deviceId required' });
  const token = await getFcmTokenForDevice(deviceId);
  if (!token) return res.status(404).json({ error: 'token not found' });
  await sendFcm(token, deviceId, 1, 'checking_update');
  res.json({ ok: true });
});

app.post('/trigger-revive', async (req, res) => {
  const deviceId = req.body.deviceId;
  if (!deviceId) return res.status(400).json({ error: 'deviceId required' });
  const snap = await statusRef.child(deviceId).once('value');
  const val = snap.val() || {};
  const token = await getFcmTokenForDevice(deviceId);
  await startJobFor(deviceId, { timestamp: val.timestamp || Date.now(), fcmToken: token });
  res.json({ started: true });
});

app.post('/stop-revive', (req, res) => {
  const deviceId = req.body.deviceId;
  if (!deviceId) return res.status(400).json({ error: 'deviceId required' });
  stopJobFor(deviceId);
  res.json({ stopped: true });
});

app.listen(PORT, () => log('[http] API running on', PORT));
