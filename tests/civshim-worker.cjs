// tests/civshim-worker.cjs — runs payloads/civshim.js verbatim inside a
// worker thread against stubbed CivSwitch loader primitives.
//
// Purpose: host the console-side payload for tests/civshim-sim.cjs. The
// payload is eval'd UNMODIFIED in a Function scope whose free variables
// (call_rop/read64/write64/malloc/nn::socket/...) are deterministic fakes
// backed by a paged memory model. The "network" is a SharedArrayBuffer
// mailbox: the main-thread test host writes request bytes into the IN area
// (recv blocks with Atomics.wait, exactly like the real synchronous ROP
// recv), the payload's send() copies into the OUT area.
// Protocol: payloads/civshim.js header comment (the system under test).
// Origin: original — BarbarismJB.
'use strict';
const fs = require('node:fs');
const {parentPort, workerData} = require('node:worker_threads');

const H = new Int32Array(workerData.sab);          // header ints
const B = new Uint8Array(workerData.sab);          // byte view
const IN_AREA = 64, IN_CAP = 65536;                // host -> shim
const OUT_AREA = IN_AREA + IN_CAP, OUT_CAP = 65536; // shim -> host
// Header layout: [0] IN_READY (0 empty, 1 data, 2 EOF), [1] IN_LEN, [2] IN_OFF,
// [8] OUT_READY, [9] OUT_LEN, [16] ACCEPT_READY (dead once accepted — its bytes
// are reused by IN data), [10] INSPECT (test-only; MUST stay inside the 64-byte
// header — any slot ≥16 overlaps live request bytes once accepted).

const sdk_base = 0x7100000000n, main_base = 0x7000000000n, HEAP = 0x5000000000n;

// ---- paged memory model ----------------------------------------------------
const pages = new Map(); // page index -> Uint8Array(4096)
const page = addr => {
  const index = Number(addr >> 12n);
  let p = pages.get(index);
  if (!p) {p = new Uint8Array(4096); pages.set(index, p);}
  return p;
};
const poke = (addr, byte) => {page(addr)[Number(addr & 0xfffn)] = byte & 0xff;};
const peek = addr => page(addr)[Number(addr & 0xfffn)];
function read64(addr) {let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(peek(addr + BigInt(i))); return v;}
function write64(addr, val) {let v = BigInt.asUintN(64, BigInt(val)); for (let i = 0; i < 8; i++) {poke(addr + BigInt(i), Number(v & 0xffn)); v >>= 8n;}}
const read32 = addr => Number(read64(addr) & 0xffffffffn);
const write8 = poke;
function writeBytesMem(addr, bytes) {for (let i = 0; i < bytes.length; i++) poke(addr + BigInt(i), bytes[i]);}
function zeroMem(addr, len) {for (let i = 0; i < len; i++) poke(addr + BigInt(i), 0);}

// ---- heap (calloc semantics: zeroed) ----------------------------------------
let heapPtr = HEAP;
const allocations = [];
function malloc(size) {
  const bytes = Number(size);
  if (!(bytes > 0) || bytes > 0x40000000) return 0n;
  const ptr = heapPtr;
  heapPtr += BigInt(Math.ceil(bytes / 8) * 8);
  zeroMem(ptr, bytes);
  allocations.push({ptr: ptr.toString(), size: bytes});
  return ptr;
}
const free = () => {};

// ---- fake native functions (call_rop targets, sdk-relative offsets) ---------
const nativeCalls = [], queries = [], sleeps = [], threads = [], joins = [];
const natives = new Map();
const def = (offset, fn) => natives.set(sdk_base + BigInt(offset), fn);
let nextTid = 0x900d0000n;
def(0x1000, (out, pageInfo, addr) => {         // svc QueryMemory wrapper
  write64(out, 0x7100000000n); write64(out + 8n, 0x100000n);
  write64(out + 16n, (5n << 32n) | 3n);         // type=3 @+16, perm=5 @+20
  queries.push(addr.toString());
  return 0n;
});
def(0x2000, ns => {sleeps.push(ns.toString()); return 0n;});   // svc SleepThread
def(0x3000, (slot, attr, start, arg) => {       // pthread_create
  const thread = nextTid++;
  write64(slot, thread);
  threads.push({slot: slot.toString(), attr: attr.toString(), start: start.toString(),
    arg: arg.toString(), thread: thread.toString()});
  return 0n;
});
def(0x3100, (thread, unused) => {joins.push(thread.toString()); return 0n;}); // pthread_join
def(0x3200, () => 0n);                                                        // pthread_exit
def(0x4000, (start, jb) => 0n);                                               // longjmp (recorded via pthread_create)
def(0x50, (a, b, c, d, e, f) => BigInt.asUintN(64, a + b + c + d + e + f));   // sum6 (CALL test)
function call_rop(fn, ...args) {
  const impl = natives.get(BigInt(fn));
  if (!impl) throw Error('sim call_rop: no native at 0x' + BigInt(fn).toString(16));
  nativeCalls.push({fn: BigInt(fn).toString(), args: args.map(String)});
  return impl(...args);
}

// ---- fake nn::socket over the SAB mailbox -----------------------------------
let boundPort = 0;
const socket = () => 3n;
const setsockopt = () => 0n;
const bind = (fd, sa) => {boundPort = (peek(sa + 2n) << 8) | peek(sa + 3n); return 0n;};
const listen = () => {parentPort.postMessage({type: 'listening', port: boundPort}); return 0n;};
function accept(fd) {
  const deadline = Date.now() + 15000;
  for (;;) {
    serviceInspect(); // park-safe inspect: the port pump is dead while we hold the thread
    if (Atomics.load(H, 16) === 1) {Atomics.store(H, 16, 0); parentPort.postMessage({type: 'accepted'}); return 7n;}
    if (Date.now() > deadline) return -1n;
    Atomics.wait(H, 16, 0, Math.min(500, deadline - Date.now()));
  }
}
const close = fd => {parentPort.postMessage({type: 'closed', fd: Number(fd)}); return 0n;};

function recv(fd, addr, len) {
  const deadline = Date.now() + 20000;
  for (;;) {
    serviceInspect(); // park-safe inspect: see accept()
    const ready = Atomics.load(H, 0);
    if (ready === 2) return 0n;                 // host signaled EOF
    if (ready === 1) {
      const total = Atomics.load(H, 1), off = Atomics.load(H, 2);
      const n = Math.min(Number(len), total - off);
      for (let i = 0; i < n; i++) poke(addr + BigInt(i), B[IN_AREA + off + i]);
      if (off + n >= total) {
        Atomics.store(H, 2, 0); Atomics.store(H, 1, 0); Atomics.store(H, 0, 0);
        Atomics.notify(H, 0);
        parentPort.postMessage({type: 'consumed'});
      } else Atomics.store(H, 2, off + n);
      return BigInt(n);
    }
    if (Date.now() > deadline) return -1n;
    Atomics.wait(H, 0, 0, Math.min(500, deadline - Date.now()));
  }
}

function send(fd, addr, len) {
  const cap = Math.min(Number(len), 32768);
  const deadline = Date.now() + 10000;
  while (Atomics.load(H, 8) === 1) {            // wait until the host drained OUT
    if (Date.now() > deadline) return -1n;
    Atomics.wait(H, 8, 1, 100);
  }
  for (let i = 0; i < cap; i++) B[OUT_AREA + i] = peek(addr + BigInt(i));
  Atomics.store(H, 9, cap);
  Atomics.store(H, 8, 1);
  Atomics.notify(H, 8);
  parentPort.postMessage({type: 'out'});
  return BigInt(cap);
}

async function log(msg) {parentPort.postMessage({type: 'log', msg: String(msg)});}
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// ---- inspect API for the test host ------------------------------------------
// While the payload server loop is parked in the fake accept/recv Atomics.wait
// loops, this thread never returns to its event loop, so parentPort messages
// queue unserviced. The host therefore raises the SAB INSPECT flag ([10]);
// the wait loops call serviceInspect() each iteration and answer from inside
// the park. Single channel, exactly one response per raised flag — a second
// port-based path would double-fire while idle and hand the next test a stale
// snapshot.
function respondInspect() {
  parentPort.postMessage({type: 'inspect', allocations, nativeCalls, queries, sleeps, threads, joins});
}
function serviceInspect() {
  if (Atomics.load(H, 10) === 1) {Atomics.store(H, 10, 0); respondInspect();}
}

// ---- run the payload, unmodified ---------------------------------------------
const source = fs.readFileSync(workerData.payloadPath, 'utf8');
const names = ['malloc', 'free', 'read64', 'write64', 'read32', 'write8', 'call_rop',
  'socket', 'setsockopt', 'bind', 'listen', 'accept', 'close', 'send', 'recv',
  'sleep', 'log', 'sdk_base', 'main_base'];
const values = [malloc, free, read64, write64, read32, write8, call_rop,
  socket, setsockopt, bind, listen, accept, close, send, recv,
  sleep, log, sdk_base, main_base];
try {
  // The payload is an async IIFE: it starts running the moment the Function
  // is invoked and keeps going on microtasks/timers.
  new Function(...names, source)(...values);
  parentPort.postMessage({type: 'ready'});
} catch (error) {
  parentPort.postMessage({type: 'boot-failed', error: error.message});
}
