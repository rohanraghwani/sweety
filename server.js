// server.js
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');

const PORT = parseInt(process.env.PORT || '5000', 10);
const DATABASE_URL = process.env.DATABASE_URL || '';
const SERVICE_ACCOUNT_PATH = process.env.SERVICE_ACCOUNT_PATH || '';
const FIREBASE_CONFIG_ENV = process.env.FIREBASE_CONFIG || '';
const FIREBASE_CONFIG_BASE64 = process.env.FIREBASE_CONFIG_BASE64 || '';

const PING_INTERVAL_MS = parseInt(process.env.PING_INTERVAL_MS || '3000', 10);
const DEFAULT_FCM_SEND_TIMEOUT_MS = parseInt(process.env.FCM_SEND_TIMEOUT_MS || '8000', 10);
const MAX_RSS_MB = parseInt(process.env.MAX_RSS_MB || '900', 10);

const PID_FILE = process.env.PID_FILE || path.join(process.cwd(), 'server.pid');
const LAST_LOG_TS_FILE = process.env.LAST_LOG_TS_FILE || path.join(process.cwd(), 'last_log_ts');

let lastLogAt = Date.now();

function isoNow(){ return new Date().toISOString(); }

try { fs.writeFileSync(PID_FILE, String(process.pid), { encoding: 'utf8' }); } catch(e){}

function writeLastLogTs(ts){
  lastLogAt = ts;
  try { fs.writeFileSync(LAST_LOG_TS_FILE, String(ts), { encoding: 'utf8' }); } catch(e){}
}
function updateLastLog(){ writeLastLogTs(Date.now()); }
function log(...a){ updateLastLog(); console.log(isoNow(), ...a); }
function warn(...a){ updateLastLog(); console.warn(isoNow(), ...a); }
function errlog(...a){ updateLastLog(); console.error(isoNow(), ...a); }

function stripQuotes(s){ if (!s || typeof s !== 'string') return s; s = s.trim(); if((s.startsWith('"')&&s.endsWith('"'))||(s.startsWith("'")&&s.endsWith("'"))) s = s.slice(1,-1); return s; }
function normalizePrivateKey(raw){ if (!raw || typeof raw !== 'string') return null; let s = stripQuotes(raw); s = s.replace(/\\\\n/g, '\\n'); s = s.replace(/\\n/g, '\n'); s = s.replace(/\r\n/g,'\n'); s = s.trim() + '\n'; s = s.replace(/\s*-----BEGIN PRIVATE KEY-----\s*/s,'-----BEGIN PRIVATE KEY-----\n'); s = s.replace(/\s*-----END PRIVATE KEY-----\s*/s,'\n-----END PRIVATE KEY-----\n'); s = s.replace(/\n{2,}/g,'\n'); return s; }
function tryParseJson(str){ if (!str || typeof str !== 'string') return null; try { return JSON.parse(str); } catch(e) { return null; } }

let SERVICE_ACCOUNT = null;
(function(){
  const type = process.env.FIREBASE_TYPE || process.env.TYPE;
  const project_id = process.env.FIREBASE_PROJECT_ID || process.env.PROJECT_ID;
  const raw_key = process.env.FIREBASE_PRIVATE_KEY || process.env.PRIVATE_KEY;
  const client_email = process.env.FIREBASE_CLIENT_EMAIL || process.env.CLIENT_EMAIL;
  if (project_id && raw_key && client_email){
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
    log('service account assembled from FIREBASE_* env fields');
  }
})();

if (!SERVICE_ACCOUNT && FIREBASE_CONFIG_ENV){
  const parsed = tryParseJson(FIREBASE_CONFIG_ENV) || tryParseJson(FIREBASE_CONFIG_ENV.replace(/\r?\n/g,'\\n'));
  if (parsed){ if (parsed.private_key) parsed.private_key = normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT = parsed; log('loaded from FIREBASE_CONFIG env'); }
}

if (!SERVICE_ACCOUNT && FIREBASE_CONFIG_BASE64){
  try {
    const raw = Buffer.from(FIREBASE_CONFIG_BASE64, 'base64').toString('utf8');
    const parsed = tryParseJson(raw) || tryParseJson(raw.replace(/\r?\n/g,'\\n'));
    if (parsed){ if (parsed.private_key) parsed.private_key = normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT = parsed; log('loaded from FIREBASE_CONFIG_BASE64'); }
  } catch(e){ warn('FIREBASE_CONFIG_BASE64 decode failed', e && e.message); }
}

if (!SERVICE_ACCOUNT && SERVICE_ACCOUNT_PATH){
  try {
    const saPath = path.isAbsolute(SERVICE_ACCOUNT_PATH) ? SERVICE_ACCOUNT_PATH : path.join(process.cwd(), SERVICE_ACCOUNT_PATH);
    if (fs.existsSync(saPath)){
      const required = require(saPath);
      if (required && required.private_key) required.private_key = normalizePrivateKey(required.private_key);
      SERVICE_ACCOUNT = required;
      log('loaded service account from SERVICE_ACCOUNT_PATH', saPath);
    }
  } catch(e){ warn('require SERVICE_ACCOUNT_PATH failed', e && e.message); }
}

if (!SERVICE_ACCOUNT){ errlog('Could not load service account. Provide FIREBASE_* env or file.'); process.exit(1); }
if (!DATABASE_URL){ errlog('DATABASE_URL is required in .env (your RTDB URL).'); process.exit(1); }

try {
  admin.initializeApp({ credential: admin.credential.cert(SERVICE_ACCOUNT), databaseURL: DATABASE_URL });
  log('firebase-admin initialized for project:', SERVICE_ACCOUNT.project_id || '(unknown)');
} catch(e){ errlog('firebase-admin initialization failed:', e && e.message); process.exit(1); }

const db = admin.database();
const statusRef = db.ref('status');
const tokensRef = db.ref('fcmTokens');

const jobs = new Map();

process.on('unhandledRejection', (r)=> { errlog('unhandledRejection', r && (r.stack||r)); });
process.on('uncaughtException', (e)=> { errlog('uncaughtException', e && (e.stack||e)); setTimeout(()=>process.exit(1),200); });

setInterval(()=>{ try{ log('diag jobs.count=', jobs.size, 'jobs=', Array.from(jobs.keys()).slice(0,20)); }catch(e){} }, 60*1000);

const connectedRef = db.ref('.info/connected');
connectedRef.on('value', snap => { log('.info/connected =', snap.val()); });

setInterval(()=>{ const rss = process.memoryUsage().rss; const mb = Math.round(rss/1024/1024); if (mb>MAX_RSS_MB){ errlog('RSS', mb, 'MB > threshold', MAX_RSS_MB, 'MB - exiting'); process.exit(1); } }, 30*1000);

async function getFcmTokenForDevice(deviceId){
  try {
    const snap = await tokensRef.child(deviceId).once('value');
    if (!snap.exists()) return null;
    const val = snap.val();
    if (typeof val === 'string') return val;
    if (val && val.token) return val.token;
    return null;
  } catch(err){ errlog('token read error', deviceId, err && err.message); return null; }
}

function buildFcmMessage(token, deviceId, attempt, type){ return { token, android:{ priority:'high', ttl:4000 }, data:{ type, deviceId:String(deviceId), attempt:String(attempt), ts:String(Date.now()) } }; }

async function sendFcm(token, deviceId, attempt, type){
  const msg = buildFcmMessage(token, deviceId, attempt, type);
  const sendPromise = admin.messaging().send(msg);
  try {
    const res = await Promise.race([ sendPromise, new Promise((_,rej)=>setTimeout(()=>rej(new Error('FCM_SEND_TIMEOUT')), DEFAULT_FCM_SEND_TIMEOUT_MS)) ]);
    log('fcm-send SUCCESS', deviceId, type, typeof res==='string' ? res : JSON.stringify(res));
    return { ok:true, res };
  } catch(err){
    if (err && err.message === 'FCM_SEND_TIMEOUT'){ errlog('fcm-send TIMEOUT', deviceId, type, `timeout=${DEFAULT_FCM_SEND_TIMEOUT_MS}ms`); return { ok:false, err:{ code:'FCM_SEND_TIMEOUT', message:`send timeout ${DEFAULT_FCM_SEND_TIMEOUT_MS}ms` } }; }
    errlog('fcm-send ERROR', deviceId, type, err && (err.code || err.message || err));
    return { ok:false, err };
  }
}

function stopJobFor(deviceId){
  const j = jobs.get(deviceId);
  if (!j) return;
  j.stopped = true;
  if (j.interval){ clearInterval(j.interval); j.interval = null; }
  if (j.watchdog){ clearInterval(j.watchdog); j.watchdog = null; }
  jobs.delete(deviceId);
  log('job stopped', deviceId);
}

async function startJobFor(deviceId, statusVal = {}){
  if (jobs.has(deviceId)){ log('job already running for', deviceId); return; }
  let token = statusVal.fcmToken || await getFcmTokenForDevice(deviceId);
  if (!token){ warn('no token for', deviceId, '- cannot start job'); return; }
  log('starting continuous revive job for', deviceId, 'token=', token && token.slice ? token.slice(0,8)+'...'+(token.slice(-6)) : '<tok>');
  const job = { deviceId, token, interval:null, watchdog:null, stopped:false, sending:false, lastAttempt:null, lastSuccess:null };
  jobs.set(deviceId, job);
  (async()=>{
    try {
      job.lastAttempt = Date.now();
      const r0 = await sendFcm(job.token, deviceId, job.lastAttempt, 'server_offline_ping');
      if (r0.ok) job.lastSuccess = Date.now();
    } catch(e){ errlog('job immediate send error', deviceId, e && (e.message || e)); }
  })();
  job.interval = setInterval(()=>{
    if (job.stopped) return clearInterval(job.interval);
    if (job.sending) return;
    (async()=>{
      job.sending = true;
      try {
        const freshToken = await getFcmTokenForDevice(deviceId);
        if (!freshToken){ errlog('token missing on refresh for', deviceId, '- stopping job'); stopJobFor(deviceId); return; }
        if (freshToken !== job.token){ log('token updated for', deviceId); job.token = freshToken; }
        let snap;
        try { snap = await statusRef.child(deviceId).once('value'); } catch(e){ warn('status read failed', deviceId, e && e.message); snap = null; }
        const val = (snap && snap.val()) || {};
        if (val.online){ log('device back online, stopping job for', deviceId); stopJobFor(deviceId); return; }
        job.lastAttempt = Date.now();
        const attemptId = String(job.lastAttempt);
        const r = await sendFcm(job.token, deviceId, attemptId, 'server_offline_ping');
        if (r.ok){ job.lastSuccess = Date.now(); } else {
          const code = r.err && (r.err.code || r.err.message || JSON.stringify(r.err));
          errlog('sendFcm failed for', deviceId, 'code=', code);
          const codeStr = String(code || '').toLowerCase();
          if (codeStr.includes('registration-token-not-registered') || codeStr.includes('invalid-registration-token') || codeStr.includes('messaging/invalid-registration-token') || codeStr.includes('not-found') || codeStr.includes('invalid-argument')){
            errlog('token invalid for', deviceId, '- removing token and stopping job');
            try { await tokensRef.child(deviceId).remove(); } catch(e){ warn('token remove failed', e && e.message); }
            stopJobFor(deviceId);
            return;
          }
        }
      } catch(e){ errlog('unexpected error for', deviceId, e && (e.stack || e.message || e)); } finally { job.sending = false; }
    })();
  }, PING_INTERVAL_MS);
  job.watchdog = setInterval(async()=>{
    try {
      if (!jobs.has(deviceId)){ clearInterval(job.watchdog); return; }
      const now = Date.now();
      const lastAttemptAge = now - (job.lastAttempt || 0);
      const lastSuccessAge = job.lastSuccess ? (now - job.lastSuccess) : null;
      if ((lastAttemptAge > (2 * PING_INTERVAL_MS)) || (lastSuccessAge !== null && lastSuccessAge > (5 * PING_INTERVAL_MS) && lastAttemptAge > (2 * PING_INTERVAL_MS))){
        warn('watchdog restarting job for', deviceId, 'lastAttemptAge=', lastAttemptAge, 'lastSuccessAge=', lastSuccessAge);
        try { stopJobFor(deviceId); } catch(e){}
        setTimeout(async()=>{
          const token2 = await getFcmTokenForDevice(deviceId);
          if (token2) startJobFor(deviceId, { timestamp: Date.now(), fcmToken: token2 }); else warn('watchdog no token to restart job for', deviceId);
        }, 500);
      }
    } catch(e){ warn('watchdog error for', deviceId, e && e.message); }
  }, Math.max(5000, PING_INTERVAL_MS * 2));
}

function handleStatusChange(childKey, val){
  const online = !!(val && val.online);
  const timestamp = (val && val.timestamp) || 0;
  log('status change', childKey, 'online=', online, 'ts=', timestamp ? new Date(timestamp).toISOString() : '(no ts)');
  if (!online){
    getFcmTokenForDevice(childKey).then(token=>{
      if (!token){ warn('no token when status reported offline for', childKey); return; }
      startJobFor(childKey, { timestamp, fcmToken: token });
    }).catch(e=>errlog('token read failed for', childKey, e && e.message));
  } else {
    if (jobs.has(childKey)) stopJobFor(childKey);
  }
}

statusRef.on('child_added', snap => handleStatusChange(snap.key, snap.val() || {}));
statusRef.on('child_changed', snap => handleStatusChange(snap.key, snap.val() || {}));
statusRef.on('child_removed', snap => { if (jobs.has(snap.key)) stopJobFor(snap.key); });

setInterval(async()=>{
  try {
    const snap = await statusRef.once('value');
    const all = snap.val() || {};
    let started = 0;
    for (const [deviceId, val] of Object.entries(all)){
      if (!val) continue;
      if (val.online){ if (jobs.has(deviceId)) stopJobFor(deviceId); continue; }
      if (!jobs.has(deviceId)){
        const token = await getFcmTokenForDevice(deviceId);
        if (token){ startJobFor(deviceId, { timestamp: val.timestamp || 0, fcmToken: token }); started++; } else { warn('no token for', deviceId); }
      }
    }
    if (started) log('recovery started jobs for', started, 'devices');
  } catch(e){ warn('recovery scan failed', e && e.message); }
}, 60*1000);

setInterval(()=>{
  try {
    const now = Date.now();
    const age = now - lastLogAt;
    const LOG_STALL_THRESHOLD_MS = parseInt(process.env.LOG_STALL_THRESHOLD_MS || '60000', 10);
    if (age > LOG_STALL_THRESHOLD_MS){
      console.error(isoNow(), '[log-stall] no logs for', age, 'ms. Exiting');
      try { if (process.stdout) process.stdout.write('', ()=>{}); if (process.stderr) process.stderr.write('', ()=>{}); } catch(e){}
      process.exit(2);
    }
  } catch(e){ try { console.error(isoNow(), '[log-stall monitor error]', e && e.message); } catch(_){} }
}, Math.max(1000, parseInt(process.env.LOG_CHECK_INTERVAL_MS || '15000', 10)));

const app = express();
app.use(bodyParser.json());

app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

app.get('/jobs', (req, res) => {
  const list = Array.from(jobs.values()).map(j => ({
    deviceId: j.deviceId,
    stopped: !!j.stopped,
    lastAttempt: j.lastAttempt ? new Date(j.lastAttempt).toISOString() : null,
    lastSuccess: j.lastSuccess ? new Date(j.lastSuccess).toISOString() : null
  }));
  res.json({ ok: true, count: jobs.size, list });
});

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
  await startJobFor(deviceId, { timestamp: val.timestamp || 0, fcmToken: token });
  res.json({ started: true });
});

app.post('/stop-revive', (req, res) => {
  const deviceId = req.body.deviceId;
  if (!deviceId) return res.status(400).json({ error: 'deviceId required' });
  stopJobFor(deviceId);
  res.json({ stopped: true });
});

app.listen(PORT, () => log('API running on', PORT));
