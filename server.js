require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const net = require('net');
let admin = require('firebase-admin');

const BASE_PORT = parseInt(process.env.PORT || '5000', 10);
const MAX_PORT_TRIES = parseInt(process.env.MAX_PORT_TRIES || '10', 10);
const DATABASE_URL = process.env.DATABASE_URL || '';
const SERVICE_ACCOUNT_PATH = process.env.SERVICE_ACCOUNT_PATH || '';
const FIREBASE_CONFIG_ENV = process.env.FIREBASE_CONFIG || '';
const FIREBASE_CONFIG_BASE64 = process.env.FIREBASE_CONFIG_BASE64 || '';
const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS || '2000', 10);
const RETRY_GAP_MS = parseInt(process.env.RETRY_GAP_MS || '2000', 10);
const MESSAGE_TTL_MS = parseInt(process.env.MESSAGE_TTL_MS || String(5 * 60 * 1000), 10);
const DEFAULT_FCM_SEND_TIMEOUT_MS = parseInt(process.env.DEFAULT_FCM_SEND_TIMEOUT_MS || '8000', 10);
const PID_FILE = process.env.PID_FILE || path.join(process.cwd(), 'server.pid');

function isoNow(){ return new Date().toISOString(); }
function log(...a){ console.log(isoNow(), ...a); }
function warn(...a){ console.warn(isoNow(), ...a); }
function errlog(...a){ console.error(isoNow(), ...a); }
const sleep = (ms)=>new Promise(r=>setTimeout(r,ms));
function stripQuotes(s){ if(!s||typeof s!=='string') return s; s=s.trim(); if((s.startsWith('"')&&s.endsWith('"'))||(s.startsWith("'")&&s.endsWith("'"))) s=s.slice(1,-1); return s; }
function normalizePrivateKey(raw){ if(!raw||typeof raw!=='string') return null; let s=stripQuotes(raw); s=s.replace(/\\\\n/g,'\\n'); s=s.replace(/\\n/g,'\n'); s=s.replace(/\r\n/g,'\n'); s=s.trim()+'\n'; s=s.replace(/\s*-----BEGIN PRIVATE KEY-----\s*/,'-----BEGIN PRIVATE KEY-----\n'); s=s.replace(/\s*-----END PRIVATE KEY-----\s*/,'\n-----END PRIVATE KEY-----\n'); s=s.replace(/\n{2,}/g,'\n'); return s; }
function tryParseJson(str){ if(!str||typeof str!=='string') return null; try{return JSON.parse(str);}catch{return null;} }

function readPidFile(){
  try{
    if(!fs.existsSync(PID_FILE)) return null;
    const s = fs.readFileSync(PID_FILE,'utf8').trim();
    if(!s) return null;
    const n = Number(s);
    return Number.isFinite(n)?n:null;
  }catch(e){ return null; }
}
function writePidFile(pid){ try{ fs.writeFileSync(PID_FILE,String(pid),'utf8'); }catch(e){} }
function removePidFile(){ try{ if(fs.existsSync(PID_FILE)) fs.unlinkSync(PID_FILE); }catch(e){} }
function isProcessRunning(pid){ if(!pid||typeof pid!=='number') return false; try{ process.kill(pid,0); return true; }catch(e){ return false; } }
async function tryKillProcess(pid, waitMs=3000){
  try{ if(!isProcessRunning(pid)) return true; try{ process.kill(pid,'SIGTERM'); }catch(e){} const dl=Date.now()+waitMs; while(Date.now()<dl){ if(!isProcessRunning(pid)) return true; await sleep(200); } if(isProcessRunning(pid)){ try{ process.kill(pid,'SIGKILL'); }catch(e){} await sleep(200); return !isProcessRunning(pid); } return true; }catch(e){ return false; }
}
async function cleanupStalePid(){
  const pid = readPidFile();
  if(!pid) return;
  if(pid===process.pid){ removePidFile(); return; }
  if(isProcessRunning(pid)){ await tryKillProcess(pid,3000); removePidFile(); } else { removePidFile(); }
}

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
      SERVICE_ACCOUNT = required; log('loaded service account from SERVICE_ACCOUNT_PATH', saPath);
    }
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
if(!SERVICE_ACCOUNT){ errlog('Could not load service account'); process.exit(1); }
if(!DATABASE_URL){ errlog('DATABASE_URL required'); process.exit(1); }

try{
  if(!admin.apps || admin.apps.length===0){
    admin.initializeApp({ credential: admin.credential.cert(SERVICE_ACCOUNT), databaseURL: DATABASE_URL });
    log('firebase initialized');
  }
}catch(e){ errlog('firebase initializeApp failed', e && e.message); process.exit(1); }

const db = admin.database();
const statusRef = db.ref('status');
const tokensRef = db.ref('fcmTokens');

async function getAllStatuses(){
  try{ const snap = await statusRef.once('value'); return snap.val() || {}; }catch(e){ errlog('getAllStatuses error', e && e.message); return {}; }
}
async function getFcmTokensForDevice(id){
  try{
    const snap = await tokensRef.child(id).once('value');
    if(!snap.exists()) return [];
    const v = snap.val();
    const set = new Set();
    const q=[v];
    while(q.length){
      const cur=q.shift();
      if(!cur) continue;
      if(typeof cur==='string'){ if(cur) set.add(cur); continue; }
      if(Array.isArray(cur)){ for(const it of cur) q.push(it); continue; }
      if(typeof cur==='object'){ for(const val of Object.values(cur)) q.push(val); continue; }
    }
    return Array.from(set);
  }catch(e){ errlog('getFcmTokensForDevice error', id, e && e.message); return []; }
}

const jobs = new Map();

function stopJob(deviceId){
  const job = jobs.get(deviceId);
  if(!job) return;
  job.stopped = true;
  clearTimeout(job.timer);
  jobs.delete(deviceId);
  log('job stopped', deviceId);
}

async function jobCycle(deviceId){
  if(jobs.has(deviceId)) return;
  const job = { deviceId, attempt: 0, stopped: false, timer: null };
  jobs.set(deviceId, job);

  const runAttempt = async () => {
    if(job.stopped) return;

    const s = await statusRef.child(deviceId).once('value').then(x=>x.val()||{}).catch(()=>({}));
    if(s.online === true){ 
      stopJob(deviceId); 
      return; 
    }

    const tokens = await getFcmTokensForDevice(deviceId);
    if(tokens.length){
      const expiryTs = Date.now() + MESSAGE_TTL_MS;
      const sends = tokens.map(token=>{
        const msg = {
          token,
          android:{ priority:'high', ttl: MESSAGE_TTL_MS },
          data:{ type:'server_ping', deviceId:String(deviceId), ts:String(Date.now()), expiry:String(expiryTs), label:`try-${job.attempt+1}` }
        };
        const sendPromise = admin.messaging().send(msg);
        const timeoutPromise = new Promise((_,rej)=>setTimeout(()=>rej(new Error('FCM_SEND_TIMEOUT')), DEFAULT_FCM_SEND_TIMEOUT_MS));
        return Promise.race([sendPromise, timeoutPromise]).then(()=>{
          log('fcm-send OK', deviceId, token.slice(0,12)+'...', `try-${job.attempt+1}`);
        }).catch(err=>{
          errlog('fcm-send FAIL', deviceId, token.slice(0,12)+'...', `try-${job.attempt+1}`, err && (err.message||err));
        });
      });
      await Promise.all(sends);
    } else {
      warn('no tokens', deviceId);
    }

    job.attempt += 1;
    if(!job.stopped){
      job.timer = setTimeout(runAttempt, RETRY_GAP_MS); // 🔁 infinite retries
    }
  };

  job.timer = setTimeout(runAttempt, 0);
}

async function pollOnce(){
  try{
    const all = await getAllStatuses();
    for(const [deviceId, val] of Object.entries(all)){
      const online = !!(val && val.online);
      if(!online){
        if(!jobs.has(deviceId)) jobCycle(deviceId);
      } else {
        if(jobs.has(deviceId)) stopJob(deviceId);
      }
    }
  }catch(e){ errlog('pollOnce error', e && e.message); }
}

let running = true;
async function mainLoop(){
  log('poll loop start', POLL_INTERVAL_MS,'ms');
  while(running){
    await pollOnce();
    await sleep(POLL_INTERVAL_MS);
  }
}

const app = express();
app.use(bodyParser.json());
app.get('/health',(req,res)=>{ res.json({ ok:true, ts:Date.now(), jobs:Array.from(jobs.keys()) }); });
app.post('/trigger',(req,res)=>{ const id = req.body && req.body.deviceId; if(!id) return res.status(400).json({error:'deviceId required'}); jobCycle(id); res.json({ started:true }); });
app.post('/stop',(req,res)=>{ const id = req.body && req.body.deviceId; if(!id) return res.status(400).json({error:'deviceId required'}); stopJob(id); res.json({ stopped:true }); });

(async function startup(){
  try{
    await cleanupStalePid();
    let chosenPort = null;
    for(let i=0;i<MAX_PORT_TRIES;i++){
      const tryPort = BASE_PORT + i;
      try{
        await new Promise((resolve,reject)=>{
          const tester = net.createServer().once('error',err=>{ tester.close?.(); reject(err); }).once('listening',()=>{ tester.close(()=>resolve()); }).listen(tryPort,'0.0.0.0');
        });
        chosenPort = tryPort; break;
      }catch(e){
        if(e && e.code==='EADDRINUSE'){ log(`port ${tryPort} in use, trying next`); continue; }
      }
    }
    if(!chosenPort){ errlog('no free port'); process.exit(1); }
    const server = app.listen(chosenPort,'0.0.0.0',()=>{
      log('API running on port', chosenPort);
      writePidFile(process.pid);
      mainLoop().catch(e=>errlog('mainLoop crashed', e && e.message));
    });
    server.on('error', async (err)=>{ errlog('server error', err && (err.message||err)); await cleanupStalePid(); process.exit(1); });
    process.on('SIGTERM',()=>{ running=false; try{ server.close(()=>{ removePidFile(); process.exit(0); }); }catch(e){ removePidFile(); process.exit(0); } });
    process.on('SIGINT',()=>{ running=false; try{ server.close(()=>{ removePidFile(); process.exit(0); }); }catch(e){ removePidFile(); process.exit(0); } });
  }catch(e){ errlog('startup error', e && (e.stack||e.message)); process.exit(1); }
})();
