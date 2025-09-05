// server.js — robust start: handle stale pid, port-in-use, firebase init guard + your poll logic
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
const express = require('express');
const bodyParser = require('body-parser');
let admin = require('firebase-admin');

// ---------- CONFIG (tweak with env) ----------
const BASE_PORT = parseInt(process.env.PORT || '5000', 10);
const MAX_PORT_TRIES = parseInt(process.env.MAX_PORT_TRIES || '10', 10);
const DATABASE_URL = process.env.DATABASE_URL || '';
const SERVICE_ACCOUNT_PATH = process.env.SERVICE_ACCOUNT_PATH || '';
const FIREBASE_CONFIG_ENV = process.env.FIREBASE_CONFIG || '';
const FIREBASE_CONFIG_BASE64 = process.env.FIREBASE_CONFIG_BASE64 || '';

const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS || '2000', 10); // every 2 sec
const BATCH_SIZE = parseInt(process.env.BATCH_SIZE || '200', 10); // per batch
const GROUP_SIZE = parseInt(process.env.GROUP_SIZE || '5', 10); // concurrent per group
const GROUP_DELAY_MS = parseInt(process.env.GROUP_DELAY_MS || '2000', 10); // wait 2s between groups
const RETRY_LIMIT = parseInt(process.env.RETRY_LIMIT || '3', 10);
const RETRY_BASE_DELAY_MS = parseInt(process.env.RETRY_BASE_DELAY_MS || '2000', 10); // base backoff
const MESSAGE_TTL_MS = parseInt(process.env.MESSAGE_TTL_MS || String(5 * 60 * 1000), 10); // 5 minutes TTL
const DEFAULT_FCM_SEND_TIMEOUT_MS = parseInt(process.env.DEFAULT_FCM_SEND_TIMEOUT_MS || '8000', 10);

// PID / logging helpers
const PID_FILE = process.env.PID_FILE || path.join(process.cwd(), 'server.pid');

function isoNow(){ return new Date().toISOString(); }
function log(...a){ console.log(isoNow(), ...a); }
function warn(...a){ console.warn(isoNow(), ...a); }
function errlog(...a){ console.error(isoNow(), ...a); }

// ---------- small util helpers ----------
function stripQuotes(s){ if(!s||typeof s!=='string') return s; s=s.trim(); if((s.startsWith('"')&&s.endsWith('"'))||(s.startsWith("'")&&s.endsWith("'"))) s=s.slice(1,-1); return s; }
function normalizePrivateKey(raw){ if(!raw||typeof raw!=='string') return null; let s=stripQuotes(raw); s=s.replace(/\\\\n/g,'\\n'); s=s.replace(/\\n/g,'\n'); s=s.replace(/\r\n/g,'\n'); s=s.trim()+'\n'; s=s.replace(/\s*-----BEGIN PRIVATE KEY-----\s*/,'-----BEGIN PRIVATE KEY-----\n'); s=s.replace(/\s*-----END PRIVATE KEY-----\s*/,'\n-----END PRIVATE KEY-----\n'); s=s.replace(/\n{2,}/g,'\n'); return s; }
function tryParseJson(str){ if(!str||typeof str!=='string') return null; try{return JSON.parse(str);}catch{return null;} }
function chunkArray(arr, n){ const out = []; for(let i=0;i<arr.length;i+=n) out.push(arr.slice(i, i+n)); return out; }
const sleepMs = sleep;

// ---------- PID / process helpers ----------
function readPidFile(){
  try{
    if(!fs.existsSync(PID_FILE)) return null;
    const s = fs.readFileSync(PID_FILE, 'utf8').trim();
    if(!s) return null;
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
  }catch(e){
    warn('readPidFile failed', e && e.message);
    return null;
  }
}

function writePidFile(pid){
  try{
    fs.writeFileSync(PID_FILE, String(pid), { encoding: 'utf8' });
    log('wrote pid file', PID_FILE, pid);
  }catch(e){
    warn('writePidFile failed', e && e.message);
  }
}

function removePidFile(){
  try{ if(fs.existsSync(PID_FILE)) fs.unlinkSync(PID_FILE); }catch(e){ warn('removePidFile failed', e && e.message); }
}

function isProcessRunning(pid){
  if(!pid || typeof pid !== 'number') return false;
  try{
    process.kill(pid, 0); // will throw if not exist / no permission
    return true;
  }catch(e){
    return false;
  }
}

async function tryKillProcess(pid, opts = { waitMs: 3000 }){
  try{
    if(!isProcessRunning(pid)) return true;
    log('attempting SIGTERM to pid', pid);
    try { process.kill(pid, 'SIGTERM'); } catch(e) { warn('SIGTERM send failed', e && e.message); }
    const deadline = Date.now() + (opts.waitMs || 3000);
    while(Date.now() < deadline){
      if(!isProcessRunning(pid)) {
        log('pid', pid, 'exited after SIGTERM');
        return true;
      }
      await sleepMs(200);
    }
    // still alive -> SIGKILL
    if(isProcessRunning(pid)){
      log('pid', pid, 'still alive -> sending SIGKILL');
      try { process.kill(pid, 'SIGKILL'); } catch(e){ warn('SIGKILL send failed', e && e.message); }
      await sleepMs(200);
      if(!isProcessRunning(pid)){ log('pid', pid, 'killed by SIGKILL'); return true; }
      warn('pid', pid, 'still running after SIGKILL');
      return false;
    }
    return true;
  }catch(e){
    warn('tryKillProcess error', e && e.message);
    return false;
  }
}

// If a stale pid exists, attempt to stop it
async function cleanupStalePid(){
  try{
    const pid = readPidFile();
    if(!pid){ log('no existing pid file'); return; }
    if(pid === process.pid){ log('pid file points to current process, overwriting'); removePidFile(); return; }
    if(isProcessRunning(pid)){
      log('found existing process pid=', pid, 'attempting graceful shutdown');
      const ok = await tryKillProcess(pid, { waitMs: 3000 });
      if(ok){ log('previous process terminated, removing pid file'); removePidFile(); return; }
      warn('could not terminate previous process pid=', pid, '— continuing but port may be in use');
    } else {
      log('stale pid file found, removing');
      removePidFile();
    }
  }catch(e){
    warn('cleanupStalePid failed', e && e.message);
  }
}

// ---------- load Firebase service account (flexible) ----------
let SERVICE_ACCOUNT = null;
if(!SERVICE_ACCOUNT && FIREBASE_CONFIG_ENV){
  const parsed = tryParseJson(FIREBASE_CONFIG_ENV) || tryParseJson(FIREBASE_CONFIG_ENV.replace(/\r?\n/g,'\\n'));
  if(parsed){ if(parsed.private_key) parsed.private_key = normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT = parsed; log('loaded service account from FIREBASE_CONFIG env'); }
}
if(!SERVICE_ACCOUNT && FIREBASE_CONFIG_BASE64){
  try{
    const raw = Buffer.from(FIREBASE_CONFIG_BASE64,'base64').toString('utf8');
    const parsed = tryParseJson(raw) || tryParseJson(raw.replace(/\r?\n/g,'\\n'));
    if(parsed){ if(parsed.private_key) parsed.private_key = normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT = parsed; log('loaded service account from FIREBASE_CONFIG_BASE64'); }
  }catch(e){ warn('FIREBASE_CONFIG_BASE64 decode failed', e && e.message); }
}
if(!SERVICE_ACCOUNT && SERVICE_ACCOUNT_PATH){
  try{
    const saPath = path.isAbsolute(SERVICE_ACCOUNT_PATH)?SERVICE_ACCOUNT_PATH:path.join(process.cwd(),SERVICE_ACCOUNT_PATH);
    if(fs.existsSync(saPath)){
      const required = require(saPath);
      if(required && required.private_key) required.private_key = normalizePrivateKey(required.private_key);
      SERVICE_ACCOUNT = required;
      log('loaded service account from SERVICE_ACCOUNT_PATH', saPath);
    } else warn('SERVICE_ACCOUNT_PATH not found', saPath);
  }catch(e){ warn('require SERVICE_ACCOUNT_PATH failed', e && e.message); }
}
if(!SERVICE_ACCOUNT){
  const project_id = process.env.FIREBASE_PROJECT_ID || process.env.FIREBASE_PROJECT || process.env.PROJECT_ID;
  const raw_key = process.env.FIREBASE_PRIVATE_KEY || process.env.PRIVATE_KEY;
  const client_email = process.env.FIREBASE_CLIENT_EMAIL || process.env.CLIENT_EMAIL;
  if(project_id && raw_key && client_email){
    SERVICE_ACCOUNT = {
      type: process.env.FIREBASE_TYPE || 'service_account',
      project_id,
      private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID || process.env.PRIVATE_KEY_ID || '',
      private_key: normalizePrivateKey(raw_key),
      client_email,
      client_id: process.env.FIREBASE_CLIENT_ID || process.env.CLIENT_ID || '',
      auth_uri: process.env.FIREBASE_AUTH_URI || process.env.AUTH_URI || 'https://accounts.google.com/o/oauth2/auth',
      token_uri: process.env.FIREBASE_TOKEN_URI || process.env.TOKEN_URI || 'https://oauth2.googleapis.com/token',
      auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL || process.env.AUTH_PROVIDER_X509_CERT_URL || 'https://www.googleapis.com/oauth2/v1/certs',
      client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL || process.env.CLIENT_X509_CERT_URL || ''
    };
    log('assembled service account from FIREBASE_* env fields');
  }
}
if(!SERVICE_ACCOUNT){ errlog('Could not load service account. Provide SERVICE_ACCOUNT_PATH or FIREBASE_CONFIG or FIREBASE_CONFIG_BASE64 or FIREBASE_* envs.'); process.exit(1); }
if(!DATABASE_URL){ errlog('DATABASE_URL required'); process.exit(1); }

// ---------- initialize firebase safely ----------
try{
  if(!admin.apps || admin.apps.length === 0){
    admin.initializeApp({ credential: admin.credential.cert(SERVICE_ACCOUNT), databaseURL: DATABASE_URL });
    log('firebase initialized');
  } else {
    log('firebase already initialized (reused existing app)');
  }
} catch(e){
  errlog('firebase initializeApp failed', e && e.message); process.exit(1);
}
const db = admin.database();
const statusRef = db.ref('status');
const tokensRef = db.ref('fcmTokens');

// ---------- helpers to fetch data ----------
async function getOnlineDeviceIds(){
  try{
    const snap = await statusRef.once('value');
    const all = snap.val() || {};
    const online = [];
    for(const [id, val] of Object.entries(all || {})){
      if(val && val.online) online.push(id);
    }
    return online;
  }catch(e){
    errlog('getOnlineDeviceIds error', e && e.message);
    return [];
  }
}

async function getFcmTokensForDevice(id){
  try{
    if(!tokensRef) return [];
    const snap = await tokensRef.child(id).once('value');
    if(!snap.exists()) return [];
    const v = snap.val();
    const set = new Set();
    if(typeof v === 'string'){ if(v) set.add(v); }
    else if(Array.isArray(v)){ for(const t of v) if(t) set.add(t); }
    else if(v && typeof v === 'object'){
      const queue = [v];
      while(queue.length){
        const cur = queue.shift();
        if(!cur) continue;
        if(typeof cur === 'string'){ if(cur) set.add(cur); continue; }
        if(Array.isArray(cur)){ for(const it of cur) queue.push(it); continue; }
        if(typeof cur === 'object'){ for(const val of Object.values(cur)) queue.push(val); }
      }
    }
    return Array.from(set);
  }catch(e){ errlog('getFcmTokensForDevice error', id, e && e.message); return []; }
}

async function getTokensForDevices(deviceIds){
  const all = [];
  for(const id of deviceIds){
    try{
      const tokens = await getFcmTokensForDevice(id);
      for(const t of tokens) all.push({ deviceId: id, token: t });
    }catch(e){
      warn('getTokensForDevices partial fail', id, e && e.message);
    }
  }
  return all;
}

// ---------- send with retry ----------
async function sendFcmTokenWithRetry(entry, label, retriesLeft = RETRY_LIMIT){
  const token = entry.token;
  const deviceId = entry.deviceId;
  const expiryTs = Date.now() + MESSAGE_TTL_MS;
  const payload = {
    token,
    android: { priority: 'high', ttl: MESSAGE_TTL_MS },
    data: { type: 'server_ping', deviceId: String(deviceId), ts: String(Date.now()), expiry: String(expiryTs), label }
  };

  const sendPromise = admin.messaging().send(payload);
  const timeoutPromise = new Promise((_, rej) => setTimeout(()=> rej(new Error('FCM_SEND_TIMEOUT')), DEFAULT_FCM_SEND_TIMEOUT_MS));
  try{
    const res = await Promise.race([sendPromise, timeoutPromise]);
    log('fcm-send OK', deviceId, token.slice(0,12)+'...', label);
    return { ok:true, deviceId, token, res };
  }catch(err){
    errlog('fcm-send FAIL', deviceId, token.slice(0,12)+'...', label, err && (err.message||err));
    if(retriesLeft > 0){
      const backoff = RETRY_BASE_DELAY_MS * Math.pow(2, RETRY_LIMIT - retriesLeft); // exponential
      warn('retrying in', backoff, 'ms for', deviceId, token.slice(0,8), 'retriesLeft=', retriesLeft-1);
      await sleepMs(backoff);
      return sendFcmTokenWithRetry(entry, label, retriesLeft-1);
    } else {
      return { ok:false, deviceId, token, error: err };
    }
  }
}

async function processBatch(tokensArray, label = 'batch'){
  if(!Array.isArray(tokensArray) || tokensArray.length === 0) return { sent:0, failed:0 };
  let sent = 0, failed = 0;
  const groups = chunkArray(tokensArray, GROUP_SIZE);
  for(let i=0;i<groups.length;i++){
    const group = groups[i];
    const promises = group.map(entry => sendFcmTokenWithRetry(entry, label));
    const results = await Promise.all(promises);
    for(const r of results){ if(r && r.ok) sent++; else failed++; }
    if(i !== groups.length - 1) await sleepMs(GROUP_DELAY_MS);
  }
  return { sent, failed };
}

// ---------- main poll loop ----------
let running = true;
let isProcessing = false;

async function mainPollLoop(){
  log('mainPollLoop started: pollIntervalMs=', POLL_INTERVAL_MS, 'batchSize=', BATCH_SIZE, 'groupSize=', GROUP_SIZE);
  while(running){
    try{
      if(isProcessing){ await sleepMs(POLL_INTERVAL_MS); continue; }
      isProcessing = true;
      const onlineIds = await getOnlineDeviceIds();
      if(!onlineIds || onlineIds.length === 0){
        isProcessing = false;
        await sleepMs(POLL_INTERVAL_MS);
        continue;
      }
      log('found online device count=', onlineIds.length);
      const deviceBatches = chunkArray(onlineIds, BATCH_SIZE);
      for(let bi=0; bi<deviceBatches.length; bi++){
        const devBatch = deviceBatches[bi];
        log(`processing device-batch ${bi+1}/${deviceBatches.length} size=${devBatch.length}`);
        const entries = await getTokensForDevices(devBatch);
        if(!entries.length){ log('no tokens found for this device batch, skipping'); continue; }
        const tokenBatches = chunkArray(entries, BATCH_SIZE);
        for(let tbi=0;tbi<tokenBatches.length;tbi++){
          const tokenBatch = tokenBatches[tbi];
          log(` processing token-batch ${tbi+1}/${tokenBatches.length} count=${tokenBatch.length}`);
          const res = await processBatch(tokenBatch, `batch-${bi+1}.${tbi+1}`);
          log(` token-batch result sent=${res.sent} failed=${res.failed}`);
        }
        await sleepMs(100);
      }
    }catch(e){
      errlog('mainPollLoop error', e && (e.stack || e.message));
    } finally {
      isProcessing = false;
    }
    await sleepMs(POLL_INTERVAL_MS);
  }
}

// ---------- HTTP API for monitoring/control ----------
const app = express();
app.use(bodyParser.json());

app.get('/health', (req, res) => {
  res.json({ ok:true, ts: Date.now(), pollInterval: POLL_INTERVAL_MS, batchSize: BATCH_SIZE, groupSize: GROUP_SIZE });
});

app.get('/status/summary', async (req,res) => {
  try{
    const online = await getOnlineDeviceIds();
    res.json({ ok:true, onlineCount: online.length, sample: online.slice(0,50) });
  }catch(e){ res.status(500).json({ error: String(e && e.message) }); }
});

app.post('/force-run', async (req,res) => {
  try{
    if(isProcessing) return res.status(409).json({ error: 'processing' });
    isProcessing = true;
    try{
      const onlineIds = await getOnlineDeviceIds();
      const deviceBatches = chunkArray(onlineIds, BATCH_SIZE);
      for(const devBatch of deviceBatches){
        const entries = await getTokensForDevices(devBatch);
        const tokenBatches = chunkArray(entries, BATCH_SIZE);
        for(const tokenBatch of tokenBatches){
          await processBatch(tokenBatch, 'manual-forcerun');
        }
      }
    }finally{ isProcessing = false; }
    res.json({ ok:true });
  }catch(e){ res.status(500).json({ error: String(e && e.message) }); }
});

// ---------- startup sequence: cleanup stale pid, find free port, start server ----------
(async function startup(){
  try{
    await cleanupStalePid();

    // try ports starting from BASE_PORT
    let chosenPort = null;
    for(let attempt = 0; attempt < MAX_PORT_TRIES; attempt++){
      const tryPort = BASE_PORT + attempt;
      try{
        // Try to create a temporary server to check port availability
        await new Promise((resolve, reject) => {
          const tester = require('net').createServer().once('error', err => {
            tester.close && tester.close();
            reject(err);
          }).once('listening', () => {
            tester.close(() => resolve());
          }).listen(tryPort, '0.0.0.0');
        });
        chosenPort = tryPort;
        break;
      }catch(e){
        if(e && e.code === 'EADDRINUSE'){
          log(`port ${tryPort} in use, trying next`);
          continue;
        } else {
          warn('port test error', e && e.message);
          continue;
        }
      }
    }

    if(!chosenPort){
      errlog('no free port found in range starting', BASE_PORT, 'tries', MAX_PORT_TRIES);
      process.exit(1);
    }

    // write chosen port to env var for clarity
    const PORT = chosenPort;
    log('starting server on port', PORT);

    // now start express listener on chosenPort
    const server = app.listen(PORT, '0.0.0.0', () => {
      log('API running on port', PORT);
      // write the pid file after listening succeed
      writePidFile(process.pid);
      // kick off main loop
      mainPollLoop().catch(e => errlog('mainPollLoop crashed', e && e.message));
    });

    // handle listen errors if any (shouldn't normally happen because we tested port)
    server.on('error', async (err) => {
      errlog('server error', err && (err.message || err));
      if(err && err.code === 'EADDRINUSE'){
        errlog('EADDRINUSE on chosen port', PORT);
        // try cleanup stale pid and exit (or optionally restart)
        await cleanupStalePid();
        process.exit(1);
      }
    });

    // cleanup on graceful shutdown
    process.on('SIGTERM', ()=>{ log('SIGTERM — stopping'); running = false; try{ server.close(()=>{ removePidFile(); process.exit(0); }); }catch(e){ removePidFile(); process.exit(0); } });
    process.on('SIGINT', ()=>{ log('SIGINT — stopping'); running = false; try{ server.close(()=>{ removePidFile(); process.exit(0); }); }catch(e){ removePidFile(); process.exit(0); } });

  }catch(e){
    errlog('startup error', e && (e.stack || e.message));
    process.exit(1);
  }
})();
