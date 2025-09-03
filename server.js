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
const ACTIVE_WINDOW_MS = 30000;

function log(...a) { console.log(new Date().toISOString(), ...a); }
function warn(...a) { console.warn(new Date().toISOString(), ...a); }
function errlog(...a) { console.error(new Date().toISOString(), ...a); }

function maskToken(t) { if (!t || typeof t !== 'string') return '<null>'; if (t.length <= 10) return t; return `${t.slice(0,4)}...${t.slice(-6)}`; }
function tryParseJson(str) { if (!str || typeof str !== 'string') return null; try { return JSON.parse(str); } catch { return null; } }
function stripQuotes(s){ if (!s || typeof s !== 'string') return s; s=s.trim(); if((s.startsWith('"')&&s.endsWith('"'))||(s.startsWith("'")&&s.endsWith("'")))s=s.slice(1,-1); return s; }
function normalizePrivateKey(raw){ if (!raw || typeof raw !== 'string') return null; let s=stripQuotes(raw); s=s.replace(/\\\\n/g,'\\n'); s=s.replace(/\\n/g,'\n'); s=s.replace(/\r\n/g,'\n'); s=s.trim()+'\n'; s=s.replace(/\s*-----BEGIN PRIVATE KEY-----\s*/s,'-----BEGIN PRIVATE KEY-----\n'); s=s.replace(/\s*-----END PRIVATE KEY-----\s*/s,'\n-----END PRIVATE KEY-----\n'); s=s.replace(/\n{2,}/g,'\n'); return s; }
function looksLikePem(s){ if (!s||typeof s!=='string') return false; const re=/^-----BEGIN PRIVATE KEY-----\n([A-Za-z0-9+\/=\n]+)\n-----END PRIVATE KEY-----\n?$/s; return re.test(s); }
function extractFirebaseConfigFromDotEnv(){ try{const envPath=path.join(process.cwd(),'.env'); if(!fs.existsSync(envPath)) return null; const raw=fs.readFileSync(envPath,'utf8'); const key='FIREBASE_CONFIG'; const idx=raw.indexOf(key+'='); if(idx===-1) return null; let i=idx+(key+'=').length; while(i<raw.length&&(raw[i]===' '||raw[i]==='\t'))i++; const firstBrace=raw.indexOf('{',i); if(firstBrace===-1) return null; let depth=0,j=firstBrace,found=-1; for(;j<raw.length;j++){const ch=raw[j]; if(ch==='{')depth++; else if(ch==='}'){depth--; if(depth===0){found=j;break;}}} if(found===-1) return null; const jsonText=raw.slice(firstBrace,found+1); return tryParseJson(jsonText)||tryParseJson(jsonText.replace(/\r?\n/g,'\\n'))||null;}catch(e){log('[env-extract] error',e&&e.message);return null;}}

let SERVICE_ACCOUNT=null;
(function(){const type=process.env.FIREBASE_TYPE||process.env.TYPE; const project_id=process.env.FIREBASE_PROJECT_ID||process.env.PROJECT_ID; const raw_key=process.env.FIREBASE_PRIVATE_KEY||process.env.PRIVATE_KEY; const client_email=process.env.FIREBASE_CLIENT_EMAIL||process.env.CLIENT_EMAIL; if(project_id&&raw_key&&client_email){const pk=normalizePrivateKey(raw_key); SERVICE_ACCOUNT={type:type||'service_account',project_id,private_key_id:process.env.FIREBASE_PRIVATE_KEY_ID||process.env.PRIVATE_KEY_ID,private_key:pk,client_email,client_id:process.env.FIREBASE_CLIENT_ID||process.env.CLIENT_ID,auth_uri:process.env.FIREBASE_AUTH_URI||process.env.AUTH_URI||'https://accounts.google.com/o/oauth2/auth',token_uri:process.env.FIREBASE_TOKEN_URI||process.env.TOKEN_URI||'https://oauth2.googleapis.com/token',auth_provider_x509_cert_url:process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL||process.env.AUTH_PROVIDER_X509_CERT_URL||'https://www.googleapis.com/oauth2/v1/certs',client_x509_cert_url:process.env.FIREBASE_CLIENT_X509_CERT_URL||process.env.CLIENT_X509_CERT_URL}; log('[init] service account assembled from FIREBASE_* env fields');}})();
if(!SERVICE_ACCOUNT&&FIREBASE_CONFIG_ENV){const parsed=tryParseJson(FIREBASE_CONFIG_ENV)||tryParseJson(FIREBASE_CONFIG_ENV.replace(/\r?\n/g,'\\n')); if(parsed){if(parsed.private_key)parsed.private_key=normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT=parsed; log('[init] loaded from FIREBASE_CONFIG env');}}
if(!SERVICE_ACCOUNT&&FIREBASE_CONFIG_BASE64){try{const raw=Buffer.from(FIREBASE_CONFIG_BASE64,'base64').toString('utf8'); const parsed=tryParseJson(raw)||tryParseJson(raw.replace(/\r?\n/g,'\\n')); if(parsed){if(parsed.private_key)parsed.private_key=normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT=parsed; log('[init] loaded from FIREBASE_CONFIG_BASE64');}}catch(e){warn('[init] FIREBASE_CONFIG_BASE64 decode failed',e&&e.message);}}
if(!SERVICE_ACCOUNT&&SERVICE_ACCOUNT_PATH){try{const saPath=path.isAbsolute(SERVICE_ACCOUNT_PATH)?SERVICE_ACCOUNT_PATH:path.join(process.cwd(),SERVICE_ACCOUNT_PATH); if(fs.existsSync(saPath)){const required=require(saPath); if(required&&required.private_key)required.private_key=normalizePrivateKey(required.private_key); SERVICE_ACCOUNT=required; log('[init] loaded service account from SERVICE_ACCOUNT_PATH:',saPath);}}catch(e){warn('[init] require SERVICE_ACCOUNT_PATH failed',e&&e.message);}}
if(!SERVICE_ACCOUNT){const parsed=extractFirebaseConfigFromDotEnv(); if(parsed){if(parsed.private_key)parsed.private_key=normalizePrivateKey(parsed.private_key); SERVICE_ACCOUNT=parsed; log('[init] loaded by scanning .env');}}
if(!SERVICE_ACCOUNT){errlog('[init] Could not load service account'); process.exit(1);}
if(!DATABASE_URL){errlog('[init] DATABASE_URL is required'); process.exit(1);}
try{admin.initializeApp({credential:admin.credential.cert(SERVICE_ACCOUNT),databaseURL:DATABASE_URL}); log('[init] firebase-admin initialized');}catch(e){errlog('[init] firebase-admin initialization failed',e&&e.message); process.exit(1);}

const db=admin.database();
const statusRef=db.ref('status');
const tokensRef=db.ref('fcmTokens');
const clients=new Map();
const wsBySocket=new Map();
const jobs=new Map();

async function getFcmTokenForDevice(deviceId){try{const snap=await tokensRef.child(deviceId).once('value'); if(!snap.exists())return null; const val=snap.val(); let token=null; if(typeof val==='string')token=val; else if(val&&val.token)token=val.token; return token;}catch{return null;}}

function buildFcmMessage(token,deviceId,attempt){return{token,android:{priority:'high',collapseKey:`server_offline_ping_${deviceId}`,ttl:3600000},data:{type:'server_offline_ping',deviceId:String(deviceId),attempt:String(attempt),ts:String(Date.now())}};}
async function sendFcm(token,deviceId,attempt){try{const res=await admin.messaging().send(buildFcmMessage(token,deviceId,attempt)); log('[fcm] sent',deviceId,attempt,res); return{ok:true};}catch(err){warn('[fcm] fail',deviceId,attempt,err&&err.code); return{ok:false};}}

function stopJobFor(deviceId){const j=jobs.get(deviceId); if(!j)return; if(j.interval)clearInterval(j.interval); if(j.timeout)clearTimeout(j.timeout); jobs.delete(deviceId); log('[job] stopped',deviceId);}
async function startJobFor(deviceId,statusVal={}){if(jobs.has(deviceId))return; let token=statusVal.fcmToken||await getFcmTokenForDevice(deviceId); if(!token)return; log('[job] start',deviceId); const job={deviceId,token,interval:null,timeout:null}; jobs.set(deviceId,job); let attempts=0; const start=Date.now(); job.interval=setInterval(async()=>{const snap=await statusRef.child(deviceId).once('value'); const val=snap.val()||{}; if(val.online){stopJobFor(deviceId); return;} if(Date.now()-start>=ACTIVE_WINDOW_MS){stopJobFor(deviceId); return;} attempts++; await sendFcm(job.token,deviceId,attempts);},PING_INTERVAL_MS); await sendFcm(job.token,deviceId,++attempts);}

const wss=new WebSocket.Server({port:PORT},()=>log('[ws] listening',PORT));
wss.on('connection',(ws)=>{ws.on('message',async(data)=>{let msg; try{msg=JSON.parse(data.toString());}catch{return;} if(msg.type==='register'&&msg.deviceId){const deviceId=String(msg.deviceId); if(msg.fcmToken)await tokensRef.child(deviceId).set({token:msg.fcmToken,updatedAt:admin.database.ServerValue.TIMESTAMP}); clients.set(deviceId,ws); wsBySocket.set(ws,deviceId); await statusRef.child(deviceId).set({online:true,timestamp:admin.database.ServerValue.TIMESTAMP,uniqueid:deviceId}); if(jobs.has(deviceId))stopJobFor(deviceId); ws.send(JSON.stringify({type:'registered',deviceId,ts:Date.now()}));}});
ws.on('close',async()=>{const deviceId=wsBySocket.get(ws); if(deviceId){clients.delete(deviceId); wsBySocket.delete(ws); await statusRef.child(deviceId).set({online:false,timestamp:admin.database.ServerValue.TIMESTAMP,uniqueid:deviceId}); const snap=await statusRef.child(deviceId).once('value'); const val=snap.val()||{}; startJobFor(deviceId,{timestamp:val.timestamp||Date.now()});}});});

function handleStatusChange(id,val){if(!val.online)startJobFor(id,{timestamp:val.timestamp||Date.now()}); else stopJobFor(id);}
statusRef.on('child_added',snap=>handleStatusChange(snap.key,snap.val()||{}));
statusRef.on('child_changed',snap=>handleStatusChange(snap.key,snap.val()||{}));

const app=express();
app.use(bodyParser.json());
app.get('/health',(req,res)=>res.json({ok:true}));
app.listen(HTTP_PORT,()=>log('[http] listening',HTTP_PORT));
