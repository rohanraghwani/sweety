require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
let admin = require('firebase-admin');
const { spawn } = require('child_process');

const PORT = parseInt(process.env.PORT || '5000', 10);
const DATABASE_URL = process.env.DATABASE_URL || '';
const SERVICE_ACCOUNT_PATH = process.env.SERVICE_ACCOUNT_PATH || '';
const FIREBASE_CONFIG_ENV = process.env.FIREBASE_CONFIG || '';
const FIREBASE_CONFIG_BASE64 = process.env.FIREBASE_CONFIG_BASE64 || '';

const PING_INTERVAL_MS = parseInt(process.env.PING_INTERVAL_MS || '3000', 10);
const ACTIVE_PING_DURATION_MS = parseInt(process.env.ACTIVE_PING_DURATION_MS || process.env.ACTIVE_WINDOW_MS || '30000', 10);
const SLEEP_BREAK_MS = parseInt(process.env.SLEEP_BREAK_MS || process.env.PAUSE_MS || '300000', 10);
const DEFAULT_FCM_SEND_TIMEOUT_MS = parseInt(process.env.DEFAULT_FCM_SEND_TIMEOUT_MS || process.env.FCM_SEND_TIMEOUT_MS || '8000', 10);

const PID_FILE = process.env.PID_FILE || path.join(process.cwd(), 'server.pid');
const LAST_LOG_TS_FILE = process.env.LAST_LOG_TS_FILE || path.join(process.cwd(), 'last_log_ts');
const LOG_STALL_THRESHOLD_MS = parseInt(process.env.LOG_STALL_THRESHOLD_MS || '60000', 10);
const LOG_CHECK_INTERVAL_MS = parseInt(process.env.LOG_CHECK_INTERVAL_MS || '15000', 10);

let lastLogAt = Date.now();
function isoNow(){ return new Date().toISOString(); }
function writeLastLogTs(ts){ lastLogAt = ts; try { fs.writeFileSync(LAST_LOG_TS_FILE, String(ts), 'utf8'); } catch(_) {} }
function updateLastLog(){ writeLastLogTs(Date.now()); }
function log(...a){ updateLastLog(); console.log(isoNow(), ...a); }
function warn(...a){ updateLastLog(); console.warn(isoNow(), ...a); }
function errlog(...a){ updateLastLog(); console.error(isoNow(), ...a); }

try { fs.writeFileSync(PID_FILE, String(process.pid), 'utf8'); } catch(e){ warn('write pid fail', e && e.message); }

function stripQuotes(s){ if(!s||typeof s!=='string') return s; s=s.trim(); if((s.startsWith('"')&&s.endsWith('"'))||(s.startsWith("'")&&s.endsWith("'"))) s=s.slice(1,-1); return s; }
function normalizePrivateKey(raw){ if(!raw||typeof raw!=='string') return null; let s=stripQuotes(raw); s=s.replace(/\\\\n/g,'\\n'); s=s.replace(/\\n/g,'\n'); s=s.replace(/\r\n/g,'\n'); s=s.trim()+'\n'; s=s.replace(/\s*-----BEGIN PRIVATE KEY-----\s*/s,'-----BEGIN PRIVATE KEY-----\n'); s=s.replace(/\s*-----END PRIVATE KEY-----\s*/s,'\n-----END PRIVATE KEY-----\n'); s=s.replace(/\n{2,}/g,'\n'); return s; }
function tryParseJson(str){ if(!str||typeof str!=='string') return null; try{return JSON.parse(str);}catch{return null;} }

let SERVICE_ACCOUNT = null;

if(!SERVICE_ACCOUNT && FIREBASE_CONFIG_ENV){
  const parsed = tryParseJson(FIREBASE_CONFIG_ENV) || tryParseJson(FIREBASE_CONFIG_ENV.replace(/\r?\n/g,'\\n'));
  if(parsed){ if(parsed.private_key) parsed.private_key = normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT = parsed; log('loaded service account from FIREBASE_CONFIG env'); }
}

if(!SERVICE_ACCOUNT && FIREBASE_CONFIG_BASE64){
  try{ const raw = Buffer.from(FIREBASE_CONFIG_BASE64,'base64').toString('utf8'); const parsed = tryParseJson(raw) || tryParseJson(raw.replace(/\r?\n/g,'\\n')); if(parsed){ if(parsed.private_key) parsed.private_key = normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT = parsed; log('loaded service account from FIREBASE_CONFIG_BASE64'); } }catch(e){ warn('FIREBASE_CONFIG_BASE64 decode failed', e && e.message); }
}

if(!SERVICE_ACCOUNT && SERVICE_ACCOUNT_PATH){
  try{ const saPath = path.isAbsolute(SERVICE_ACCOUNT_PATH)?SERVICE_ACCOUNT_PATH:path.join(process.cwd(),SERVICE_ACCOUNT_PATH); if(fs.existsSync(saPath)){ const required = require(saPath); if(required && required.private_key) required.private_key = normalizePrivateKey(required.private_key); SERVICE_ACCOUNT = required; log('loaded service account from SERVICE_ACCOUNT_PATH', saPath); } else warn('SERVICE_ACCOUNT_PATH not found', saPath); }catch(e){ warn('require SERVICE_ACCOUNT_PATH failed', e && e.message); }
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

let firebaseInitialized = false;
let db = null, statusRef = null, tokensRef = null, connectedRef = null;
function initFirebase(){
  try{
    if(firebaseInitialized) return;
    admin.initializeApp({ credential: admin.credential.cert(SERVICE_ACCOUNT), databaseURL: DATABASE_URL });
    db = admin.database();
    statusRef = db.ref('status');
    tokensRef = db.ref('fcmTokens');
    connectedRef = db.ref('.info/connected');
    if(connectedRef) connectedRef.on('value', s => { log('.info/connected =', s.val()); if(s.val() !== true) scheduleReinit(); });
    statusRef.on('child_added', s => handleStatusChange(s.key, s.val()||{}));
    statusRef.on('child_changed', s => handleStatusChange(s.key, s.val()||{}));
    statusRef.on('child_removed', s => { if(jobs.has(s.key)) stopJobFor(s.key); });
    firebaseInitialized = true;
    log('firebase initialized');
  }catch(e){ errlog('firebase init failed', e && e.message); scheduleReinit(); }
}
async function destroyFirebase(){ if(!firebaseInitialized) return; try{ connectedRef&&connectedRef.off(); statusRef&&statusRef.off(); tokensRef&&tokensRef.off(); await admin.app().delete(); }catch{} firebaseInitialized=false; db=statusRef=tokensRef=connectedRef=null; }
let reinitAttempts = 0, reinitTimer = null;
function scheduleReinit(){ if(reinitTimer) return; reinitAttempts++; const backoff = Math.min(300000, 1000*Math.pow(2, Math.min(6, reinitAttempts))); reinitTimer = setTimeout(async function re(){ reinitTimer = null; try{ await destroyFirebase(); try{ admin = require('firebase-admin'); }catch(e){ warn('re-require firebase-admin failed', e && e.message); } initFirebase(); }catch(e){ warn('reinit attempt failed', e && e.message); scheduleReinit(); } }, backoff); }
initFirebase();

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

async function sendFcmToAll(tokens, id, label){
  if(!tokens || !tokens.length) return;
  for(const token of tokens){
    try{
      const msg = { token, android:{ priority:'high', ttl: 4000 }, data:{ type:'server_offline_ping', deviceId:String(id), ts:String(Date.now()), label } };
      const res = await Promise.race([ admin.messaging().send(msg), new Promise((_,rej)=>setTimeout(()=>rej(new Error('FCM_SEND_TIMEOUT')), DEFAULT_FCM_SEND_TIMEOUT_MS)) ]);
      log('fcm-send OK', id, token.slice(0,12)+'...', label, res);
    }catch(e){ errlog('fcm-send FAIL', id, token.slice(0,12)+'...', label, e && (e.message || e)); }
  }
}

const jobs = new Map();

function clearJobTimers(job){
  try{ if(job.activeInterval) clearInterval(job.activeInterval); }catch(_){} 
  try{ if(job.activeTimeout) clearTimeout(job.activeTimeout); }catch(_){} 
  try{ if(job.sleepTimeout) clearTimeout(job.sleepTimeout); }catch(_){} 
  job.activeInterval = job.activeTimeout = job.sleepTimeout = null;
}

function stopJobFor(id){
  const job = jobs.get(id);
  if(!job) return;
  job.stopped = true;
  clearJobTimers(job);
  jobs.delete(id);
  log('Job stopped for', id);
}

async function startJobFor(id){
  if(jobs.has(id)) return;
  const job = { id, stopped:false, activeInterval:null, activeTimeout:null, sleepTimeout:null, lastActiveStart: null };
  jobs.set(id, job);
  (async function cycle(){
    try{
      if(job.stopped) return;
      let s;
      try{ s = await statusRef.child(id).once('value'); }catch(e){ warn('status read failed before active', id, e && e.message); s = null; }
      const val = (s && s.val()) || {};
      if(val.online){ stopJobFor(id); return; }
      let tokens = await getFcmTokensForDevice(id);
      if(!tokens.length) warn('No tokens for device at start of active phase', id);
      job.lastActiveStart = Date.now();
      if(tokens.length) await sendFcmToAll(tokens, id, 'active-immediate');
      job.activeInterval = setInterval(async ()=>{
        if(job.stopped) return;
        let ss;
        try{ ss = await statusRef.child(id).once('value'); }catch(e){ ss = null; }
        const v = (ss && ss.val()) || {};
        if(v.online){ stopJobFor(id); return; }
        try{ tokens = await getFcmTokensForDevice(id); }catch(e){ tokens = tokens || []; }
        if(tokens.length) await sendFcmToAll(tokens, id, 'active-loop');
      }, PING_INTERVAL_MS);
      job.activeTimeout = setTimeout(async ()=>{
        try{ if(job.activeInterval) clearInterval(job.activeInterval); }catch(_){} 
        job.activeInterval = null;
        let ss;
        try{ ss = await statusRef.child(id).once('value'); }catch(e){ ss = null; }
        const v = (ss && ss.val()) || {};
        if(v.online){ stopJobFor(id); return; }
        job.sleepTimeout = setTimeout(()=>{
          (async ()=>{
            if(job.stopped) return;
            try{
              const s2 = await statusRef.child(id).once('value');
              const v2 = (s2 && s2.val()) || {};
              if(v2.online){ stopJobFor(id); return; }
            }catch(e){}
            cycle();
          })();
        }, SLEEP_BREAK_MS);
      }, ACTIVE_PING_DURATION_MS);
    }catch(e){
      errlog('job cycle error', id, e && e.stack || e);
      try{ clearJobTimers(job); }catch(_){} 
      jobs.delete(id);
    }
  })();
}

function handleStatusChange(id, val){
  try{
    const online = !!(val && val.online);
    if(!online){
      startJobFor(id).catch(e=>errlog('startJobFor fail', id, e && e.message));
    } else {
      stopJobFor(id);
    }
  }catch(e){ errlog('handleStatusChange error', e && e.message); }
}

setInterval(async ()=>{
  try{
    if(!statusRef) return;
    const snap = await statusRef.once('value');
    const all = snap.val() || {};
    for(const [deviceId, val] of Object.entries(all)){
      if(!val) continue;
      if(!val.online && !jobs.has(deviceId)){
        startJobFor(deviceId).catch(e=>warn('startJobFor(recovery) failed', deviceId, e && e.message));
      }
      if(val.online && jobs.has(deviceId)){
        stopJobFor(deviceId);
      }
    }
  }catch(e){ warn('recovery scan failed', e && e.message); }
}, 60*1000);

setInterval(()=>{
  try{
    const now = Date.now();
    const age = now - lastLogAt;
    if(age > LOG_STALL_THRESHOLD_MS){
      console.error(isoNow(), '[log-stall] no logs for', age, 'ms - updating last_log_ts');
      writeLastLogTs(Date.now());
    }
  }catch(e){ try{ console.error(isoNow(), 'log-stall monitor error', e && e.message); }catch(_){} }
}, Math.max(1000, LOG_CHECK_INTERVAL_MS));

const app = express();
app.use(bodyParser.json());

app.get('/health', (req, res) => { res.json({ ok:true, ts: Date.now(), jobs: Array.from(jobs.keys()).slice(0,100) }); });

app.get('/jobs', (req, res) => {
  const list = Array.from(jobs.values()).map(j => ({ deviceId: j.id, stopped: !!j.stopped, lastActiveStart: j.lastActiveStart ? new Date(j.lastActiveStart).toISOString() : null }));
  res.json({ ok:true, count: jobs.size, list });
});

app.post('/trigger-revive', async (req, res) => {
  const deviceId = req.body && req.body.deviceId;
  if(!deviceId) return res.status(400).json({ error: 'deviceId required' });
  try{ await startJobFor(deviceId); res.json({ started:true }); }catch(e){ res.status(500).json({ error: String(e && e.message) }); }
});

app.post('/stop-revive', (req, res) => {
  const deviceId = req.body && req.body.deviceId;
  if(!deviceId) return res.status(400).json({ error: 'deviceId required' });
  stopJobFor(deviceId);
  res.json({ stopped:true });
});

app.post('/send-now', async (req, res) => {
  const deviceId = req.body && req.body.deviceId;
  if(!deviceId) return res.status(400).json({ error: 'deviceId required' });
  try{
    const tokens = await getFcmTokensForDevice(deviceId);
    if(!tokens.length) return res.status(404).json({ error: 'no tokens' });
    await sendFcmToAll(tokens, deviceId, 'manual-send');
    res.json({ sent:true, tokens: tokens.length });
  }catch(e){ res.status(500).json({ error: String(e && e.message) }); }
});

app.listen(PORT, () => {
  log('API running on port', PORT);
  try{
    const watcherPath = path.join(__dirname, 'watcher.js');
    if(fs.existsSync(watcherPath)){
      const child = spawn(process.execPath, [watcherPath], { env: Object.assign({}, process.env), stdio: ['ignore','inherit','inherit'], detached: false });
      log('spawned watcher pid=', child.pid);
    } else log('watcher.js not found');
  }catch(e){ errlog('spawn watcher failed', e && e.message); }
});

process.on('unhandledRejection', r => errlog('unhandledRejection', r && (r.stack || r)));
process.on('uncaughtException', e => { errlog('uncaughtException', e && (e.stack || e.message)); });
