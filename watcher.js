const fs = require('fs');
const path = require('path');

const PID_FILE = process.env.PID_FILE || path.join(process.cwd(), 'server.pid');
const LAST_LOG_TS_FILE = process.env.LAST_LOG_TS_FILE || path.join(process.cwd(), 'last_log_ts');
const LOG_FILE = process.env.SERVER_LOG_FILE || path.join(process.cwd(), 'server.log');

const CHECK_INTERVAL_MS = parseInt(process.env.CHECK_INTERVAL_MS || process.env.WATCHER_CHECK_INTERVAL_MS || '15000', 10);
const LOG_STALL_THRESHOLD_MS = parseInt(process.env.WATCHER_THRESHOLD_MS || process.env.LOG_WATCHER_THRESHOLD_MS || process.env.LOG_STALL_THRESHOLD_MS || '60000', 10);
const KILL_TIMEOUT_MS = parseInt(process.env.KILL_TIMEOUT_MS || '5000', 10);
const STATUS_HEARTBEAT_MS = parseInt(process.env.STATUS_HEARTBEAT_MS || '5000', 10);
const TAIL_POLL_MS = parseInt(process.env.TAIL_POLL_MS || '1000', 10);

function isoNow(){ return new Date().toISOString(); }

function readNumberFile(filePath){
  try {
    if (!fs.existsSync(filePath)) return null;
    const s = fs.readFileSync(filePath, 'utf8').trim();
    if (!s) return null;
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
  } catch(e) {
    console.error(isoNow(), 'read error', filePath, e && e.message);
    return null;
  }
}

function killPid(pid, signal){
  try {
    process.kill(pid, signal);
    console.log(isoNow(), `sent ${signal} to pid ${pid}`);
    return true;
  } catch(e) {
    console.error(isoNow(), `failed to send ${signal} to pid ${pid}:`, e && e.message);
    return false;
  }
}

async function checkOnce(){
  const pid = readNumberFile(PID_FILE);
  const lastLogTs = readNumberFile(LAST_LOG_TS_FILE);
  const now = Date.now();

  if (!pid) {
    console.warn(isoNow(), 'no pid file at', PID_FILE);
  }
  if (!lastLogTs) {
    console.warn(isoNow(), 'no last_log_ts at', LAST_LOG_TS_FILE);
  }

  const age = lastLogTs ? (now - lastLogTs) : Infinity;
  console.log(isoNow(), `pid=${pid || 'NONE'} lastLogAgeMs=${age === Infinity ? 'NEVER' : age} threshold=${LOG_STALL_THRESHOLD_MS}`);

  if (age > LOG_STALL_THRESHOLD_MS) {
    console.error(isoNow(), `detected log-stall age ${age}ms > threshold ${LOG_STALL_THRESHOLD_MS}ms. restarting pid ${pid || 'UNKNOWN'}`);
    if (pid && killPid(pid, 'SIGTERM')) {
      await new Promise(res => setTimeout(res, KILL_TIMEOUT_MS));
      try {
        process.kill(pid, 0);
        console.warn(isoNow(), `pid ${pid} alive after SIGTERM -> SIGKILL`);
        killPid(pid, 'SIGKILL');
      } catch (e) {
        console.log(isoNow(), `pid ${pid} no longer exists`);
      }
    } else {
      console.error(isoNow(), `couldn't send SIGTERM to pid ${pid || 'UNKNOWN'}`);
    }
  }
}

console.log(isoNow(), 'watcher starting CHECK_INTERVAL_MS=', CHECK_INTERVAL_MS, 'LOG_STALL_THRESHOLD_MS=', LOG_STALL_THRESHOLD_MS, 'STATUS_HEARTBEAT_MS=', STATUS_HEARTBEAT_MS, 'LOG_FILE=', LOG_FILE);

setInterval(()=>{
  checkOnce().catch(e => console.error(isoNow(), 'unexpected error', e && e.stack || e));
}, Math.max(1000, CHECK_INTERVAL_MS));

checkOnce().catch(e => console.error(isoNow(), 'initial check error', e && e.stack || e));

let tailPos = 0;
let tailFd = null;

function openTail(){
  try {
    if (tailFd) { try { fs.closeSync(tailFd); } catch(e){}; tailFd = null; }
    if (!fs.existsSync(LOG_FILE)) return;
    tailFd = fs.openSync(LOG_FILE, 'r');
    const stat = fs.fstatSync(tailFd);
    tailPos = stat.size;
  } catch(e){
    tailFd = null;
  }
}

function pollTail(){
  try {
    if (!fs.existsSync(LOG_FILE)){
      if (tailFd) { try { fs.closeSync(tailFd); } catch(e){}; tailFd = null; }
      return;
    }
    if (!tailFd) openTail();
    if (!tailFd) return;
    const stat = fs.fstatSync(tailFd);
    if (stat.size > tailPos){
      const toRead = stat.size - tailPos;
      const buf = Buffer.allocUnsafe(toRead);
      const read = fs.readSync(tailFd, buf, 0, toRead, tailPos);
      tailPos += read;
      const text = buf.toString('utf8', 0, read);
      process.stdout.write(text);
    } else if (stat.size < tailPos){
      tailPos = 0;
      try { fs.closeSync(tailFd); } catch(e){}; tailFd = null;
      openTail();
    }
  } catch(e){
    try { console.error(isoNow(), 'tail error', e && e.message); } catch(_){}
  }
}

setInterval(()=>{
  pollTail();
}, Math.max(200, TAIL_POLL_MS));

setInterval(()=>{
  try {
    const pid = readNumberFile(PID_FILE);
    const lastLogTs = readNumberFile(LAST_LOG_TS_FILE);
    const now = Date.now();
    const age = lastLogTs ? (now - lastLogTs) : Infinity;
    if (!pid) {
      console.log(isoNow(), `heartbeat: missing pid file at ${PID_FILE}`);
    }
    if (!lastLogTs) {
      console.log(isoNow(), `heartbeat: missing last_log_ts at ${LAST_LOG_TS_FILE}`);
    }
    if (age <= LOG_STALL_THRESHOLD_MS) {
      console.log(isoNow(), `everything normal pid=${pid || 'NONE'} lastLogAgeMs=${age === Infinity ? 'NEVER' : age}`);
    } else {
      console.log(isoNow(), `STALE pid=${pid || 'NONE'} lastLogAgeMs=${age === Infinity ? 'NEVER' : age}`);
    }
  } catch(e) {
    console.error(isoNow(), 'heartbeat error', e && e.message);
  }
}, Math.max(1000, STATUS_HEARTBEAT_MS));
