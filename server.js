require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
let admin = require('firebase-admin'); // let so re-require works
const { spawn } = require('child_process');

const PORT = parseInt(process.env.PORT || '5000', 10);
const DATABASE_URL = process.env.DATABASE_URL || '';
const SERVICE_ACCOUNT_PATH = process.env.SERVICE_ACCOUNT_PATH || '';
const FIREBASE_CONFIG_ENV = process.env.FIREBASE_CONFIG || '';
const FIREBASE_CONFIG_BASE64 = process.env.FIREBASE_CONFIG_BASE64 || '';

const PING_INTERVAL_MS = parseInt(process.env.PING_INTERVAL_MS || '3000', 10);
const DEFAULT_FCM_SEND_TIMEOUT_MS = parseInt(process.env.FCM_SEND_TIMEOUT_MS || '8000', 10);
const MAX_RSS_MB = parseInt(process.env.MAX_RSS_MB || '900', 10);

// NEW: immediate token retry config
const IMMEDIATE_TOKEN_RETRY_MS = parseInt(process.env.IMMEDIATE_TOKEN_RETRY_MS || '2000', 10); // 2s default
const IMMEDIATE_TOKEN_RETRY_MAX = parseInt(process.env.IMMEDIATE_TOKEN_RETRY_MAX || '0', 10); // 0 = infinite

const PID_FILE = process.env.PID_FILE || path.join(process.cwd(), 'server.pid');
const LAST_LOG_TS_FILE = process.env.LAST_LOG_TS_FILE || path.join(process.cwd(), 'last_log_ts');

let lastLogAt = Date.now();
function isoNow(){ return new Date().toISOString(); }
function writeLastLogTs(ts){ lastLogAt = ts; try{ fs.writeFileSync(LAST_LOG_TS_FILE, String(ts), 'utf8'); }catch{} }
function updateLastLog(){ writeLastLogTs(Date.now()); }
function log(...a){ updateLastLog(); console.log(isoNow(), ...a); }
function warn(...a){ updateLastLog(); console.warn(isoNow(), ...a); }
function errlog(...a){ updateLastLog(); console.error(isoNow(), ...a); }

try { fs.writeFileSync(PID_FILE, String(process.pid), 'utf8'); } catch {}

function stripQuotes(s){ if(!s||typeof s!=='string')return s; s=s.trim(); if((s.startsWith('"')&&s.endsWith('"'))||(s.startsWith("'")&&s.endsWith("'")))s=s.slice(1,-1); return s; }
function normalizePrivateKey(raw){ if(!raw||typeof raw!=='string')return null; let s=stripQuotes(raw); s=s.replace(/\\\\n/g,'\\n'); s=s.replace(/\\n/g,'\n'); s=s.replace(/\r\n/g,'\n'); s=s.trim()+'\n'; s=s.replace(/\s*-----BEGIN PRIVATE KEY-----\s*/s,'-----BEGIN PRIVATE KEY-----\n'); s=s.replace(/\s*-----END PRIVATE KEY-----\s*/s,'\n-----END PRIVATE KEY-----\n'); s=s.replace(/\n{2,}/g,'\n'); return s; }
function tryParseJson(str){ if(!str||typeof str!=='string')return null; try{return JSON.parse(str);}catch{return null;} }

// --- Service account load (env, base64, file) ---
let SERVICE_ACCOUNT=null;
(function(){
  const type=process.env.FIREBASE_TYPE||process.env.TYPE;
  const project_id=process.env.FIREBASE_PROJECT_ID||process.env.PROJECT_ID;
  const raw_key=process.env.FIREBASE_PRIVATE_KEY||process.env.PRIVATE_KEY;
  const client_email=process.env.FIREBASE_CLIENT_EMAIL||process.env.CLIENT_EMAIL;
  if(project_id&&raw_key&&client_email){
    SERVICE_ACCOUNT={ type:type||'service_account', project_id, private_key_id:process.env.FIREBASE_PRIVATE_KEY_ID||process.env.PRIVATE_KEY_ID, private_key:normalizePrivateKey(raw_key), client_email, client_id:process.env.FIREBASE_CLIENT_ID||process.env.CLIENT_ID, auth_uri:process.env.FIREBASE_AUTH_URI||process.env.AUTH_URI||'https://accounts.google.com/o/oauth2/auth', token_uri:process.env.FIREBASE_TOKEN_URI||process.env.TOKEN_URI||'https://oauth2.googleapis.com/token', auth_provider_x509_cert_url:process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL||process.env.AUTH_PROVIDER_X509_CERT_URL||'https://www.googleapis.com/oauth2/v1/certs', client_x509_cert_url:process.env.FIREBASE_CLIENT_X509_CERT_URL||process.env.CLIENT_X509_CERT_URL };
    log('service account assembled from FIREBASE_* env fields');
  }
})();
if(!SERVICE_ACCOUNT&&FIREBASE_CONFIG_ENV){
  const parsed=tryParseJson(FIREBASE_CONFIG_ENV)||tryParseJson(FIREBASE_CONFIG_ENV.replace(/\r?\n/g,'\\n'));
  if(parsed){ if(parsed.private_key)parsed.private_key=normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT=parsed; log('loaded from FIREBASE_CONFIG env'); }
}
if(!SERVICE_ACCOUNT&&FIREBASE_CONFIG_BASE64){
  try{ const raw=Buffer.from(FIREBASE_CONFIG_BASE64,'base64').toString('utf8'); const parsed=tryParseJson(raw)||tryParseJson(raw.replace(/\r?\n/g,'\\n')); if(parsed){ if(parsed.private_key)parsed.private_key=normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT=parsed; log('loaded from FIREBASE_CONFIG_BASE64'); } }catch(e){ warn('FIREBASE_CONFIG_BASE64 decode failed',e&&e.message); }
}
if(!SERVICE_ACCOUNT&&SERVICE_ACCOUNT_PATH){
  try{ const saPath=path.isAbsolute(SERVICE_ACCOUNT_PATH)?SERVICE_ACCOUNT_PATH:path.join(process.cwd(),SERVICE_ACCOUNT_PATH); if(fs.existsSync(saPath)){ const required=require(saPath); if(required&&required.private_key)required.private_key=normalizePrivateKey(required.private_key); SERVICE_ACCOUNT=required; log('loaded service account from SERVICE_ACCOUNT_PATH',saPath); } }catch(e){ warn('require SERVICE_ACCOUNT_PATH failed',e&&e.message); }
}
if(!SERVICE_ACCOUNT){ errlog('Could not load service account'); process.exit(1); }
if(!DATABASE_URL){ errlog('DATABASE_URL is required'); process.exit(1); }

// --- Firebase init/destroy/reinit ---
let firebaseInitialized=false,reinitAttempts=0,db=null,statusRef=null,tokensRef=null,connectedRef=null;
function initFirebase(){
  try{
    if(firebaseInitialized)return;
    admin.initializeApp({credential:admin.credential.cert(SERVICE_ACCOUNT),databaseURL:DATABASE_URL});
    db=admin.database();
    statusRef=db.ref('status'); tokensRef=db.ref('fcmTokens'); connectedRef=db.ref('.info/connected');
    connectedRef.on('value',s=>{ log('.info/connected =',s.val()); if(s.val()!==true) scheduleReinit(); });
    statusRef.on('child_added',s=>handleStatusChange(s.key,s.val()||{}));
    statusRef.on('child_changed',s=>handleStatusChange(s.key,s.val()||{}));
    statusRef.on('child_removed',s=>{ if(jobs.has(s.key)) stopJobFor(s.key); });
    firebaseInitialized=true; reinitAttempts=0; log('firebase initialized');
  }catch(e){ errlog('firebase init failed',e&&e.message); scheduleReinit(); }
}
async function destroyFirebase(){ if(!firebaseInitialized)return; try{ connectedRef&&connectedRef.off(); statusRef&&statusRef.off(); tokensRef&&tokensRef.off(); await admin.app().delete(); }catch{} firebaseInitialized=false; db=statusRef=tokensRef=connectedRef=null; }
let reinitTimer=null;
function scheduleReinit(){ if(reinitTimer)return; reinitTimer=setTimeout(async function re(){ reinitAttempts++; try{ await destroyFirebase(); try{ admin=require('firebase-admin'); }catch(e){ warn('re-require firebase-admin failed',e&&e.message);} initFirebase(); if(firebaseInitialized){clearTimeout(reinitTimer); reinitTimer=null; return;} }catch{} const backoff=Math.min(300000,1000*Math.pow(2,Math.min(6,reinitAttempts))); reinitTimer=setTimeout(re,backoff); },1000); }
initFirebase();

// --- jobs + FCM ---
const jobs=new Map();
// track active immediate-token retry loops so we don't start duplicates
const immediateRetryMap = new Map();

process.on('unhandledRejection',r=>errlog('unhandledRejection',r&&(r.stack||r)));
process.on('uncaughtException',e=>{ errlog('uncaughtException',e&&(e.stack||e)); setTimeout(()=>process.exit(1),200); });
setInterval(()=>{ try{ log('diag jobs.count=',jobs.size,'jobs=',Array.from(jobs.keys()).slice(0,20)); }catch{} },60000);
setInterval(()=>{ const mb=Math.round(process.memoryUsage().rss/1024/1024); if(mb>MAX_RSS_MB){ errlog('RSS',mb,'> threshold',MAX_RSS_MB,'- exiting'); process.exit(1);} },30000);

async function getFcmTokenForDevice(id){ try{ if(!tokensRef)return null; const snap=await tokensRef.child(id).once('value'); if(!snap.exists())return null; const v=snap.val(); if(typeof v==='string')return v; if(v&&v.token)return v.token; return null; }catch(e){ errlog('token read error',id,e&&e.message); return null; } }
function buildFcmMessage(token,id,attempt,type){ return {token,android:{priority:'high',ttl:4000},data:{type,deviceId:String(id),attempt:String(attempt),ts:String(Date.now())}}; }
async function sendFcm(token,id,attempt,type,maxRetries=3){ let a=0,lastErr=null; while(a<maxRetries){a++; try{ const msg=buildFcmMessage(token,id,attempt,type); const res=await Promise.race([admin.messaging().send(msg),new Promise((_,rej)=>setTimeout(()=>rej(new Error('FCM_SEND_TIMEOUT')),DEFAULT_FCM_SEND_TIMEOUT_MS))]); log('fcm-send SUCCESS',id,type,res); return{ok:true,res}; }catch(e){ lastErr=e; errlog('fcm-send attempt',a,'failed',id,type,e&&e.message); if(a<maxRetries)await new Promise(r=>setTimeout(r,500*a)); }} return{ok:false,err:lastErr}; }

// helper to cancel an active immediate retry loop for a device (called when device becomes online)
function cancelImmediateRetry(id){
  const item = immediateRetryMap.get(id);
  if (item && item.stop) {
    try { item.stop(); } catch(e) {}
  }
  immediateRetryMap.delete(id);
}

// --- Immediate revive ping (now: if no token, keep retrying every 2s until token arrives) ---
// Behavior: triggerImmediateRevivePing returns quickly. If token missing, it starts a background loop
// that checks every IMMEDIATE_TOKEN_RETRY_MS and sends FCM when token appears. Duplicate loops prevented.
async function triggerImmediateRevivePing(id){
  try {
    // if already a retry loop active for this device, don't spawn another
    if (immediateRetryMap.has(id)){
      log('immediate revive: retry loop already running for', id);
      return { ok:false, reason:'retrying' };
    }

    const token = await getFcmTokenForDevice(id);
    if (token){
      // token present now — send immediately
      const r = await sendFcm(token, id, `immediate-${Date.now()}`, 'server_offline_ping', 1);
      return r.ok ? { ok:true } : { ok:false, err:r.err };
    }

    // no token now — start background retry loop
    log('immediate revive: no token for', id, '- starting background retry every', IMMEDIATE_TOKEN_RETRY_MS, 'ms');

    // create a cancellable controller
    let stopped = false;
    const stop = () => { stopped = true; };
    immediateRetryMap.set(id, { stop });

    // background async loop (non-blocking)
    (async()=>{
      let attempts = 0;
      while(!stopped){
        attempts++;
        // respect optional max attempts (0 => infinite)
        if (IMMEDIATE_TOKEN_RETRY_MAX > 0 && attempts > IMMEDIATE_TOKEN_RETRY_MAX){
          warn('immediate revive: max retry attempts reached for', id, '- stopping background retry');
          break;
        }

        await new Promise(r => setTimeout(r, IMMEDIATE_TOKEN_RETRY_MS));

        if (stopped) break;

        try {
          // if device became online, stop retrying
          try {
            const s = await statusRef.child(id).once('value');
            const val = s && s.val();
            if (val && val.online){
              log('immediate revive: device became online during retry, stopping retries for', id);
              break;
            }
          } catch(e2){
            // continue even if status read fails
          }

          const retryToken = await getFcmTokenForDevice(id);
          if (stopped) break;
          if (retryToken){
            log('immediate revive: token appeared for', id, '- sending FCM now (attempt', attempts,')');
            try {
              const r = await sendFcm(retryToken, id, `immediate-retry-${Date.now()}`, 'server_offline_ping', 1);
              if (r && r.ok){
                log('immediate revive: send success for', id, 'after', attempts, 'attempt(s)');
              } else {
                errlog('immediate revive: send failed for', id, 'after token appeared', r && r.err);
              }
            } catch(e3){
              errlog('immediate revive: unexpected send error for', id, e3 && e3.message);
            }
            break; // stop loop after successful send (or attempt)
          } else {
            log('immediate revive: token still missing for', id, 'attempt', attempts);
          }
        } catch(e){
          errlog('immediate revive: retry loop error for', id, e && e.message);
        }
      } // end while

      // cleanup
      immediateRetryMap.delete(id);
      log('immediate revive: background retry stopped for', id);
    })();

    return { ok:false, reason:'retrying' };
  } catch(e){
    errlog('immediate revive error', id, e && e.message);
    // ensure cleanup on top-level error
    immediateRetryMap.delete(id);
    return { ok:false, err:e };
  }
}

// --- Job start/stop ---
function stopJobFor(id){ const j=jobs.get(id); if(!j)return; j.stopped=true; if(j.interval)clearInterval(j.interval); if(j.watchdog)clearInterval(j.watchdog); jobs.delete(id); log('job stopped',id); }
async function startJobFor(id,statusVal={}){
  if(jobs.has(id)){ log('job already running for', id); return; }
  let token=statusVal.fcmToken||await getFcmTokenForDevice(id);
  if(!token){ warn('no token for',id,'- cannot start job'); return; }
  log('starting continuous revive job for', id);
  const job={deviceId:id,token,interval:null,watchdog:null,stopped:false,sending:false,lastAttempt:null,lastSuccess:null}; jobs.set(id,job);

  // immediate attempt as part of job start (keeps original logic)
  (async()=>{
    try {
      job.lastAttempt = Date.now();
      const r0 = await sendFcm(job.token, id, job.lastAttempt, 'server_offline_ping');
      if (r0.ok) job.lastSuccess = Date.now();
    } catch(e){ errlog('job immediate send error', id, e && (e.message || e)); }
  })();

  job.interval = setInterval(()=>{
    if (job.stopped) return clearInterval(job.interval);
    if (job.sending) return;
    (async()=>{
      job.sending = true;
      try {
        const freshToken = await getFcmTokenForDevice(id);
        if (!freshToken){ errlog('token missing on refresh for', id, '- stopping job'); stopJobFor(id); return; }
        if (freshToken !== job.token){ log('token updated for', id); job.token = freshToken; }
        let snap;
        try { snap = await statusRef.child(id).once('value'); } catch(e){ warn('status read failed', id, e && e.message); snap = null; }
        const val = (snap && snap.val()) || {};
        if (val.online){ log('device back online, stopping job for', id); stopJobFor(id); return; }
        job.lastAttempt = Date.now();
        const attemptId = String(job.lastAttempt);
        const r = await sendFcm(job.token, id, attemptId, 'server_offline_ping');
        if (r.ok){ job.lastSuccess = Date.now(); } else {
          const code = r.err && (r.err.code || r.err.message || JSON.stringify(r.err));
          errlog('sendFcm failed for', id, 'code=', code);
          const codeStr = String(code || '').toLowerCase();
          if (codeStr.includes('registration-token-not-registered') || codeStr.includes('invalid-registration-token') || codeStr.includes('messaging/invalid-registration-token') || codeStr.includes('not-found') || codeStr.includes('invalid-argument')){
            errlog('token invalid for', id, '- removing token and stopping job');
            try { await tokensRef.child(id).remove(); } catch(e){ warn('token remove failed', e && e.message); }
            stopJobFor(id);
            return;
          }
        }
      } catch(e){ errlog('unexpected error for', id, e && (e.stack || e.message || e)); } finally { job.sending = false; }
    })();
  }, PING_INTERVAL_MS);

  job.watchdog = setInterval(async()=>{
    try {
      if (!jobs.has(id)){ clearInterval(job.watchdog); return; }
      const now = Date.now();
      const lastAttemptAge = now - (job.lastAttempt || 0);
      const lastSuccessAge = job.lastSuccess ? (now - job.lastSuccess) : null;
      if ((lastAttemptAge > (2 * PING_INTERVAL_MS)) || (lastSuccessAge !== null && lastSuccessAge > (5 * PING_INTERVAL_MS) && lastAttemptAge > (2 * PING_INTERVAL_MS))){
        warn('watchdog restarting job for', id);
        try { stopJobFor(id); } catch(e){}
        setTimeout(async()=>{
          const token2 = await getFcmTokenForDevice(id);
          if (token2) startJobFor(id, { timestamp: Date.now(), fcmToken: token2 }); else warn('watchdog no token to restart job for', id);
        }, 500);
      }
    } catch(e){ warn('watchdog error for', id, e && e.message); }
  }, Math.max(5000, PING_INTERVAL_MS * 2));
}

// ---------- Status change handler ----------
function handleStatusChange(id, val){
  const online = !!(val && val.online);
  log('status change', id, 'online=', online);

  if (!online){
    // start immediate ping + background retry until token appears
    triggerImmediateRevivePing(id);

    // ensure continuous revive job is running
    getFcmTokenForDevice(id).then(token=>{
      if (!token){
        warn('no token when status reported offline for', id);
        return;
      }
      startJobFor(id, { fcmToken: token });
    }).catch(e=>errlog('token read failed for', id, e && e.message));
  } else {
    // device is online -> stop job and cancel any background immediate retries
    if (jobs.has(id)) stopJobFor(id);
    cancelImmediateRetry(id);
  }
}

// ---------- Recovery scan ----------
setInterval(async()=>{
  try {
    if (!statusRef) return;
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

// ---------- Log stall monitor ----------
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

// ---------- Express API ----------
const app = express(); app.use(bodyParser.json());
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
  cancelImmediateRetry(deviceId);
  res.json({ stopped: true });
});

app.listen(PORT, () => {
  log('API running on', PORT);
  try {
    const child = spawn(process.execPath, [path.join(__dirname,'watcher.js')], {
      env: Object.assign({}, process.env),
      stdio: ['ignore','inherit','inherit'],
      detached: false
    });
    log('spawned watcher pid=', child.pid);
  } catch(e){ errlog('spawn watcher failed', e && e.message); }
});
