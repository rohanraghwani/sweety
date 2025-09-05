// watcher.js — monitor + restart + tail (fixed)
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const PID_FILE = process.env.PID_FILE || path.join(process.cwd(), 'server.pid');
const LAST_LOG_TS_FILE = process.env.LAST_LOG_TS_FILE || path.join(process.cwd(), 'last_log_ts');
const LOG_FILE = process.env.SERVER_LOG_FILE || path.join(process.cwd(), 'server.log');
const SERVER_PATH = process.env.SERVER_PATH || path.join(__dirname, 'server.js');

const CHECK_INTERVAL_MS = parseInt(process.env.CHECK_INTERVAL_MS || '5000', 10);
const LOG_STALL_THRESHOLD_MS = parseInt(process.env.LOG_STALL_THRESHOLD_MS || '60000', 10);
const KILL_TIMEOUT_MS = parseInt(process.env.KILL_TIMEOUT_MS || '5000', 10);
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

function isProcessAlive(pid){
  try { process.kill(pid, 0); return true; } catch(e){ return false; }
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

async function spawnServer(){
  try{
    if(!fs.existsSync(SERVER_PATH)) { console.error(isoNow(), 'server file not found', SERVER_PATH); return null; }
    const child = spawn(process.execPath, [SERVER_PATH], {
      env: Object.assign({}, process.env),
      stdio: 'ignore',
      detached: true
    });
    child.unref();
    try { fs.writeFileSync(PID_FILE, String(child.pid), 'utf8'); } catch(e) { console.error(isoNow(), 'failed to write pid file for spawned process', e && e.message); }
    console.log(isoNow(), 'spawned new server pid=', child.pid);
    return child.pid;
  }catch(e){
    console.error(isoNow(), 'spawnServer failed', e && e.message);
    return null;
  }
}

async function checkOnce(){
  const pid = readNumberFile(PID_FILE);
  const lastLogTs = readNumberFile(LAST_LOG_TS_FILE);
  const now = Date.now();
  const age = lastLogTs ? (now - lastLogTs) : Infinity;

  console.log(isoNow(), `pid=${pid || 'NONE'} lastLogAgeMs=${age === Infinity ? 'NEVER' : age} threshold=${LOG_STALL_THRESHOLD_MS}`);

  // If server process missing, try spawn
  if (!pid || !isProcessAlive(pid)) {
    console.warn(isoNow(), `server missing (pid=${pid||'NONE'}). spawning server.`);
    await spawnServer();
    return;
  }

  // If logs stale beyond threshold -> restart flow
  if (age > LOG_STALL_THRESHOLD_MS) {
    console.error(isoNow(), `detected log-stall age ${age}ms > threshold ${LOG_STALL_THRESHOLD_MS}ms. restarting pid ${pid}`);
    // Try graceful
    if (killPid(pid, 'SIGTERM')) {
      await new Promise(res => setTimeout(res, KILL_TIMEOUT_MS));
      if (isProcessAlive(pid)) {
        console.warn(isoNow(), `pid ${pid} alive after SIGTERM -> SIGKILL`);
        killPid(pid, 'SIGKILL');
        // give short time for OS to reap
        await new Promise(res => setTimeout(res, 200));
      } else {
        console.log(isoNow(), `pid ${pid} exited after SIGTERM`);
      }
    } else {
      console.error(isoNow(), `couldn't send SIGTERM to pid ${pid}`);
    }
    // spawn new server
    await spawnServer();
  }
}

console.log(isoNow(), 'watcher starting CHECK_INTERVAL_MS=', CHECK_INTERVAL_MS, 'LOG_STALL_THRESHOLD_MS=', LOG_STALL_THRESHOLD_MS, 'LOG_FILE=', LOG_FILE, 'SERVER_PATH=', SERVER_PATH);

// ensure server running at start
(async ()=>{
  try {
    const pid = readNumberFile(PID_FILE);
    if(!pid || !isProcessAlive(pid)){
      console.log(isoNow(), 'no running pid found — spawning server');
      await spawnServer();
    } else {
      console.log(isoNow(), 'server pid exists:', pid);
    }
  } catch(e) {
    console.error(isoNow(), 'initial spawn check failed', e && e.stack || e);
  }
})();

// periodic checks
setInterval(()=>{ checkOnce().catch(e => console.error(isoNow(), 'unexpected error', e && e.stack || e)); }, Math.max(1000, CHECK_INTERVAL_MS));
checkOnce().catch(e => console.error(isoNow(), 'initial check error', e && e.stack || e));

// --- tail logic (optional, safe) ---
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
setInterval(()=>{ pollTail(); }, Math.max(200, TAIL_POLL_MS));

// handle graceful shutdown of watcher itself
process.on('SIGINT', ()=>{ console.log(isoNow(), 'watcher SIGINT — exiting'); process.exit(0); });
process.on('SIGTERM', ()=>{ console.log(isoNow(), 'watcher SIGTERM — exiting'); process.exit(0); });
