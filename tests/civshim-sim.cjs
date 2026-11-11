// tests/civshim-sim.cjs — console-side simulation: payloads/civshim.js is
// eval'd (unmodified) against stubbed loader primitives and driven over a
// real byte-exact channel.
//
// Purpose: verify the payload's side of the BarbarismJB wire protocol — hello
// layout, every op, degrade-then-upload lifecycle, coalesced WRITE with
// byte-exact overshoot flush (including unaligned tails and multi-chunk
// streams), malformed-frame handling, the null-never-downgrades merge rule,
// THREAD_CREATE argument order, and listener self-heal after a dropped
// connection. This is the suite class that caught the take() double-count
// deadlock, the bridge header word offsets, and the scratch-boundary BigInt
// mix during development.
// Protocol: payloads/civshim.js header comment (authoritative).
// Companion: tests/civshim-worker.cjs (the stub host environment).
// Origin: original — BarbarismJB.
// Run: node tests/civshim-sim.cjs   (exit 0 = all scenarios passed)
'use strict';
const {Worker} = require('node:worker_threads');
const path = require('node:path');
const assert = require('node:assert');

const PROJECT = path.resolve(__dirname, '..');
const WORKER = path.join(__dirname, 'civshim-worker.cjs');
const PAYLOAD = path.join(PROJECT, 'payloads', 'civshim.js');
const SDK = 0x7100000000n, MAIN = 0x7000000000n;

const IN_AREA = 64, OUT_AREA = 64 + 65536;
const REQUEST_MAGIC = 0x43495631;
const OP = {PING: 1, CALL: 2, READ: 3, WRITE: 4, QUERY: 5, ALLOC: 6, FREE: 7,
  THREAD_CREATE: 8, THREAD_JOIN: 9, SLEEP: 10, UPD_OFFSETS: 11};

// ---- mailbox + scripted host -------------------------------------------------
class HostSide {
  constructor(sab) {
    this.H = new Int32Array(sab);
    this.B = new Uint8Array(sab);
    this.chunks = [];
    this.waiters = [];
    this.drainedWaiters = [];
    this.events = [];
    this.eventWaiters = [];
  }
  onMessage(message) {
    if (message.type === 'out') {
      const length = Atomics.load(this.H, 9);
      this.chunks.push(Buffer.from(this.B.subarray(OUT_AREA, OUT_AREA + length)));
      Atomics.store(this.H, 8, 0);
      Atomics.notify(this.H, 8);
      for (const waiter of this.waiters.splice(0)) waiter();
    } else if (message.type === 'consumed') {
      for (const waiter of this.drainedWaiters.splice(0)) waiter();
    } else this.events.push(message);
    for (const waiter of this.eventWaiters.splice(0)) waiter();
  }
  async waitFor(predicate, timeout = 15000, what = 'event') {
    const deadline = Date.now() + timeout;
    for (;;) {
      // Consume the matched event: each event is awaited exactly once. A
      // non-consuming find made every later wait re-match the OLDEST backlog
      // entry (e.g. a stale inspect snapshot from a previous step).
      const index = this.events.findIndex(predicate);
      if (index !== -1) return this.events.splice(index, 1)[0];
      if (Date.now() > deadline) throw Error('timed out waiting for ' + what);
      await new Promise(resolve => {this.eventWaiters.push(resolve); setTimeout(resolve, 20);});
    }
  }
  readExact(length, timeout = 15000) {
    const deadline = Date.now() + timeout;
    const pull = async () => {
      for (;;) {
        if (this.chunks.length && this.chunks[0].length >= length) {
          const first = this.chunks[0];
          const out = first.subarray(0, length);
          if (first.length === length) this.chunks.shift();
          else this.chunks[0] = first.subarray(length);
          return out;
        }
        if (this.chunks.length > 1) {
          this.chunks[0] = Buffer.concat([this.chunks.shift(), this.chunks[0]]);
          continue;
        }
        if (Date.now() > deadline) throw Error('timed out reading ' + length + ' bytes');
        await new Promise(resolve => {this.waiters.push(resolve); setTimeout(resolve, 20);});
      }
    };
    return pull();
  }
  async writeChunk(bytes, timeout = 15000) {
    // Wait for the worker to fully consume the previous chunk.
    const deadline = Date.now() + timeout;
    while (Atomics.load(this.H, 0) === 1) {
      if (Date.now() > deadline) throw Error('timed out waiting for the shim to consume');
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    this.B.set(bytes, IN_AREA);
    Atomics.store(this.H, 2, 0);
    Atomics.store(this.H, 1, bytes.length);
    Atomics.store(this.H, 0, 1);
    Atomics.notify(this.H, 0);
  }
  connect() {Atomics.store(this.H, 16, 1); Atomics.notify(this.H, 16);}
  eof() {Atomics.store(this.H, 0, 2); Atomics.notify(this.H, 0);}
}

// ---- raw framing helpers (independent of engine code: this suite tests the
// payload itself, so the host side is hand-rolled here) ------------------------
function frame(op, id, payload = Buffer.alloc(0), raw = Buffer.alloc(0)) {
  const header = Buffer.alloc(16);
  header.writeUInt32LE(REQUEST_MAGIC, 0);
  header.writeUInt32LE(op, 4);
  header.writeUInt32LE(id, 8);
  header.writeUInt32LE(payload.length, 12);
  return Buffer.concat([header, payload, raw]);
}
const u64 = value => {const b = Buffer.alloc(8); b.writeBigUInt64LE(value); return b;};
const u32 = value => {const b = Buffer.alloc(4); b.writeUInt32LE(value >>> 0); return b;};

async function readResponse(host, {timeout = 15000} = {}) {
  const header = await host.readExact(20, timeout);
  const op = header.readUInt32LE(4) >>> 0, id = header.readUInt32LE(8);
  const length = header.readUInt32LE(12), status = header.readUInt32LE(16);
  const payload = length ? await host.readExact(length, timeout) : Buffer.alloc(0);
  return {op, id, length, status, payload};
}

// ---- scenarios ----------------------------------------------------------------
async function main() {
  const sab = new SharedArrayBuffer(64 + 65536 + 65536);
  const host = new HostSide(sab);
  const worker = new Worker(WORKER, {workerData: {sab, payloadPath: PAYLOAD}});
  worker.on('message', message => host.onMessage(message));
  worker.on('error', error => {host.events.push({type: 'worker-error', error: error.message});});
  // Inspects go exclusively via the SAB flag ([10] — header-only slot; ≥16
  // would corrupt live request bytes). Single channel on purpose: the fake
  // accept/recv wait loops service it while parked, and each request yields
  // exactly one response. (A second, port-based channel would double-fire
  // while idle and leave a stale snapshot queued for the next test.)
  const requestInspect = () => {
    Atomics.store(host.H, 10, 1);
    Atomics.notify(host.H, 10);
  };
  const watchdog = setTimeout(() => {
    console.error('civshim-sim: FATAL: watchdog fired (suite hung)');
    worker.terminate();
    process.exit(1);
  }, 120000);
  watchdog.unref();
  let passed = 0;
  const step = async (name, body) => {
    try {await body(); passed++; console.log('  ok  ' + name);}
    catch (error) {console.error('  FAIL ' + name + ': ' + error.message); throw error;}
  };

  try {
    const listening = await host.waitFor(m => m.type === 'listening', 15000, 'listener');
    const port = listening.port;
    assert.strictEqual(port, 39381, 'bind port');

    // -- hello ---------------------------------------------------------------
    host.connect();
    let id = 0;
    const nextId = () => ++id & 0xffffffff;
    await step('hello: 128-byte CIV1 header layout', async () => {
      const hello = await host.readExact(128);
      assert.strictEqual(hello.readUInt32LE(0), 0x31564943, 'magic');
      assert.strictEqual(hello.readUInt32LE(4), 1, 'version');
      assert.strictEqual(hello.readUInt32LE(8), 2, 'platform');
      assert.strictEqual(hello.readUInt32LE(12), 0, 'reserved');
      assert.strictEqual(hello.readBigUInt64LE(16), MAIN, 'mainBase');
      assert.strictEqual(hello.readBigUInt64LE(24), 0n, 'mainSize unknown pre-upload');
      assert.strictEqual(hello.readBigUInt64LE(32), SDK, 'sdkBase');
      assert.strictEqual(hello.readBigUInt64LE(40), 0n, 'sdkSize unknown pre-upload');
      assert.ok(Number(hello.readBigUInt64LE(48)) >= 0x5000000000, 'scratch in heap');
      assert.strictEqual(hello.readBigUInt64LE(56), 0x1000n, 'scratch size');
      for (const offset of [64, 72, 80, 88]) assert.strictEqual(hello.readBigUInt64LE(offset), 0n, 'svc word ' + offset);
      assert.ok(hello.subarray(96, 128).equals(Buffer.alloc(32)), 'reserved tail zero');
    });
    await step('hello: 256-byte JSON offsets trailer (all null pre-M0)', async () => {
      const trailer = await host.readExact(256);
      const text = trailer.toString('utf8').split('\0')[0];
      const dict = JSON.parse(text);
      assert.deepStrictEqual(Object.keys(dict).sort(), ['sdk_offsets', 'svc']);
      assert.strictEqual(dict.svc.query_memory, null);
      assert.strictEqual(dict.sdk_offsets.longjmp, null);
    });

    // -- ops before the offsets upload (degraded mode) -------------------------
    await step('PING echo', async () => {
      await host.writeChunk(frame(OP.PING, nextId(), Buffer.from('sim-ping')));
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 0);
      assert.strictEqual(reply.payload.toString(), 'sim-ping');
    });
    await step('PING zero-length payload', async () => {
      await host.writeChunk(frame(OP.PING, nextId()));
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 0);
      assert.strictEqual(reply.length, 0);
    });
    await step('PING echo capped at 32 bytes', async () => {
      await host.writeChunk(frame(OP.PING, nextId(), Buffer.alloc(40, 0xab)));
      const reply = await readResponse(host);
      assert.strictEqual(reply.length, 32);
    });
    await step('CALL with six arguments (sum6 native)', async () => {
      const payload = Buffer.concat([u64(SDK + 0x50n), u32(6), u32(0),
        u64(1n), u64(2n), u64(3n), u64(4n), u64(5n), u64(6n)]);
      await host.writeChunk(frame(OP.CALL, nextId(), payload));
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 0);
      assert.strictEqual(reply.payload.readBigUInt64LE(), 21n);
    });
    let scratch = 0n;
    await step('ALLOC returns a heap pointer', async () => {
      await host.writeChunk(frame(OP.ALLOC, nextId(), u64(0x1000n)));
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 0);
      scratch = reply.payload.readBigUInt64LE();
      assert.ok(scratch >= 0x5000000000n && scratch < 0x5100000000n && scratch % 8n === 0n, 'ptr 0x' + scratch.toString(16));
    });
    await step('ALLOC size 0 rejected as bad request', async () => {
      await host.writeChunk(frame(OP.ALLOC, nextId(), u64(0n)));
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 3);
    });
    await step('ALLOC above the 1 GiB cap rejected before malloc', async () => {
      await host.writeChunk(frame(OP.ALLOC, nextId(), u64(0x100000000n)));
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 3);
    });
    await step('WRITE fully coalesced (overshoot flush) + unaligned tail, read back', async () => {
      const data = Buffer.from(Array.from({length: 100}, (_, i) => (i * 7 + 3) & 0xff));
      // One burst: 16-byte header + 16-byte payload + 100 raw bytes. The
      // framing layer buffers past the frame; the overshoot must land at the
      // target byte-exactly (storeBytesExact RMW on the 4-byte tail).
      await host.writeChunk(frame(OP.WRITE, nextId(), Buffer.concat([u64(scratch), u64(BigInt(data.length))]), data));
      assert.strictEqual((await readResponse(host)).status, 0);
      await host.writeChunk(frame(OP.READ, nextId(), Buffer.concat([u64(scratch), u64(BigInt(data.length))])));
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 0);
      assert.ok(reply.payload.equals(data), 'round-trip differs');
    });
    await step('WRITE spanning multiple recv chunks (mailbox chunking)', async () => {
      const data = Buffer.from(Array.from({length: 200003}, (_, i) => (i * 31 + 7) & 0xff));
      const request = frame(OP.WRITE, nextId(), Buffer.concat([u64(scratch), u64(BigInt(data.length))]), data);
      for (let at = 0; at < request.length; at += 60000)
        await host.writeChunk(request.subarray(at, Math.min(at + 60000, request.length)));
      assert.strictEqual((await readResponse(host)).status, 0);
      await host.writeChunk(frame(OP.READ, nextId(), Buffer.concat([u64(scratch), u64(BigInt(data.length))])));
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 0);
      assert.ok(reply.payload.equals(data), 'large round-trip differs');
    });
    await step('READ len 0 rejected as bad request', async () => {
      await host.writeChunk(frame(OP.READ, nextId(), Buffer.concat([u64(scratch), u64(0n)])));
      assert.strictEqual((await readResponse(host)).status, 3);
    });
    await step('READ implausible address rejected', async () => {
      await host.writeChunk(frame(OP.READ, nextId(), Buffer.concat([u64(1n), u64(16n)])));
      assert.strictEqual((await readResponse(host)).status, 3);
    });
    await step('READ span past 2^47 rejected', async () => {
      await host.writeChunk(frame(OP.READ, nextId(), Buffer.concat([u64((1n << 47n) - 0x10n), u64(0x100n)])));
      assert.strictEqual((await readResponse(host)).status, 3);
    });
    await step('QUERY/SLEEP/THREAD_* answer unavailable before the upload', async () => {
      await host.writeChunk(frame(OP.QUERY, nextId(), u64(scratch)));
      assert.strictEqual((await readResponse(host)).status, 1);
      await host.writeChunk(frame(OP.SLEEP, nextId(), u64(1000n)));
      assert.strictEqual((await readResponse(host)).status, 1);
      await host.writeChunk(frame(OP.THREAD_CREATE, nextId(), u64(scratch)));
      assert.strictEqual((await readResponse(host)).status, 1);
    });
    await step('short QUERY payload rejected without killing the connection', async () => {
      await host.writeChunk(frame(OP.QUERY, nextId(), u32(1)));   // 4 bytes, must be 8
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 3);
      await host.writeChunk(frame(OP.PING, nextId(), Buffer.from('still-alive')));
      assert.strictEqual((await readResponse(host)).payload.toString(), 'still-alive');
    });
    await step('CALL argc/payload mismatch rejected', async () => {
      const payload = Buffer.concat([u64(SDK + 0x50n), u32(2), u32(0), u64(1n)]); // argc 2 but only one arg
      await host.writeChunk(frame(OP.CALL, nextId(), payload));
      assert.strictEqual((await readResponse(host)).status, 3);
    });
    await step('CALL unaligned/zero target rejected', async () => {
      await host.writeChunk(frame(OP.CALL, nextId(), Buffer.concat([u64(0n), u32(0), u32(0)])));
      assert.strictEqual((await readResponse(host)).status, 3);
      await host.writeChunk(frame(OP.CALL, nextId(), Buffer.concat([u64(SDK + 0x51n), u32(0), u32(0)])));
      assert.strictEqual((await readResponse(host)).status, 3);
    });

    // -- UPD_OFFSETS lifecycle --------------------------------------------------
    const upload = {svc: {query_memory: 0x1000, sleep_thread: 0x2000,
      connect_to_named_service: 0x1100, send_sync_request: 0x1200},
      sdk_offsets: {longjmp: 0x4000, pthread_create: 0x3000, pthread_join: 0x3100, pthread_exit: 0x3200},
      modules: {main: {size: 38297600}, sdk: {size: 6160384}}};
    await step('UPD_OFFSETS: upload, merged reply, features go live', async () => {
      await host.writeChunk(frame(OP.UPD_OFFSETS, nextId(), Buffer.from(JSON.stringify(upload))));
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 0);
      const merged = JSON.parse(reply.payload.toString());
      assert.strictEqual(merged.svc.query_memory, 0x1000);
      assert.strictEqual(merged.sdk_offsets.pthread_create, 0x3000);
      assert.strictEqual(merged.modules.main.size, 38297600);
      await host.writeChunk(frame(OP.QUERY, nextId(), u64(scratch)));
      const query = await readResponse(host);
      assert.strictEqual(query.status, 0);
      assert.strictEqual(query.payload.readBigUInt64LE(0), SDK, 'region base');
      assert.strictEqual(query.payload.readBigUInt64LE(8), 0x100000n, 'region size');
      assert.strictEqual(query.payload.readBigUInt64LE(16), 3n, 'type');
      assert.strictEqual(query.payload.readBigUInt64LE(24), 5n, 'perm');
    });
    await step('SLEEP reaches the svc wrapper', async () => {
      await host.writeChunk(frame(OP.SLEEP, nextId(), u64(1500000n)));
      assert.strictEqual((await readResponse(host)).status, 0);
      requestInspect();
      const state = await host.waitFor(m => m.type === 'inspect', 5000, 'inspect');
      assert.deepStrictEqual(state.sleeps, ['1500000']);
    });
    let workerThread = null;
    await step('THREAD_CREATE argument order (slot, NULL, longjmp, jbPtr)', async () => {
      const jb = scratch + 0x400n;
      await host.writeChunk(frame(OP.THREAD_CREATE, nextId(), u64(jb)));
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 0);
      const thread = reply.payload.readBigUInt64LE();
      requestInspect();
      const state = await host.waitFor(m => m.type === 'inspect', 5000, 'inspect');
      assert.strictEqual(state.threads.length, 1);
      workerThread = state.threads[0];
      assert.strictEqual(BigInt(workerThread.start), SDK + 0x4000n, 'start routine = longjmp');
      assert.strictEqual(BigInt(workerThread.arg), jb, 'argument = jbPtr');
      assert.strictEqual(workerThread.attr, '0', 'attr = NULL');
      assert.strictEqual(BigInt(workerThread.thread), thread, 'reply echoes the slot pthread_t');
      await host.writeChunk(frame(OP.THREAD_JOIN, nextId(), u64(thread)));
      assert.strictEqual((await readResponse(host)).status, 0);
    });
    await step('UPD_OFFSETS: null never downgrades a live value', async () => {
      await host.writeChunk(frame(OP.UPD_OFFSETS, nextId(), Buffer.from(JSON.stringify({svc: {query_memory: null}}))));
      const reply = await readResponse(host);
      const merged = JSON.parse(reply.payload.toString());
      assert.strictEqual(merged.svc.query_memory, 0x1000, 'live value kept');
    });
    await step('UPD_OFFSETS rejects malformed input', async () => {
      await host.writeChunk(frame(OP.UPD_OFFSETS, nextId(), Buffer.from('{not json')));
      assert.strictEqual((await readResponse(host)).status, 3);
      await host.writeChunk(frame(OP.UPD_OFFSETS, nextId(), Buffer.from(JSON.stringify({svc: {query_memory: 'fast'}}))));
      assert.strictEqual((await readResponse(host)).status, 3);
      await host.writeChunk(frame(OP.UPD_OFFSETS, nextId(), Buffer.from(JSON.stringify({modules: {main: 5}}))));
      assert.strictEqual((await readResponse(host)).status, 3);
    });
    await step('FREE accepts a live pointer', async () => {
      await host.writeChunk(frame(OP.FREE, nextId(), u64(scratch)));
      assert.strictEqual((await readResponse(host)).status, 0);
    });

    // -- malformed frames: respond, then drop ------------------------------------
    await step('unknown op: bad-request reply, then connection drop', async () => {
      await host.writeChunk(frame(99, nextId()));
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 3);
      await host.waitFor(m => m.type === 'closed' && m.fd === 7, 5000, 'fd close');
    });
    await step('listener self-heals: a second connection is served', async () => {
      host.connect();
      const hello = await host.readExact(128, 10000);
      assert.strictEqual(hello.readUInt32LE(0), 0x31564943);
      await host.readExact(256);
    });
    await step('bad request magic: hard drop without a reply', async () => {
      const broken = Buffer.alloc(16);
      broken.writeUInt32LE(0xdeadbeef, 0);
      broken.writeUInt32LE(OP.PING, 4);
      await host.writeChunk(broken);
      await host.waitFor(m => m.type === 'closed' && m.fd === 7, 5000, 'fd close after bad magic');
    });
    await step('oversized payloadLen: bad-request reply, then drop', async () => {
      host.connect();
      await host.readExact(128 + 256);
      const oversized = Buffer.alloc(16);
      oversized.writeUInt32LE(REQUEST_MAGIC, 0);
      oversized.writeUInt32LE(OP.PING, 4);
      oversized.writeUInt32LE(1, 8);
      oversized.writeUInt32LE(0x500000, 12);     // above MAX_STREAM (0x400000)
      await host.writeChunk(oversized);
      const reply = await readResponse(host);
      assert.strictEqual(reply.status, 3);
      await host.waitFor(m => m.type === 'closed' && m.fd === 7, 5000, 'fd close after oversize');
    });
    await step('host EOF ends the connection cleanly', async () => {
      host.connect();
      await host.readExact(128 + 256);
      host.eof();
      await host.waitFor(m => m.type === 'log' && /connection ended/.test(m.msg), 5000, 'connection-ended log');
    });

    console.log('civshim-sim: ' + passed + ' scenarios passed');
  } finally {
    clearTimeout(watchdog);
    await worker.terminate();
  }
  return 0;
}

if (require.main === module)
  main().then(() => process.exit(0), error => {console.error('civshim-sim: FAILED: ' + error.message); process.exit(1);});
module.exports = {main};
