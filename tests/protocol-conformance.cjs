// tests/protocol-conformance.cjs — the REAL host stack (engine/lib/connection.cjs,
// engine/lib/bridge.cjs) against a fake console over real loopback sockets.
//
// Purpose: verify the host's side of the BarbarismJB wire protocol — CIV1
// hello parsing and validation (including malformed greetings), the
// serialized request/response discipline, every op round-trip through the
// Civshim client class, error statuses, the never-replay timeout, framing
// edge cases (coalesced responses, zero-length payloads, oversized or
// mismatched responses), and the loopback HTTP bridge front (serve()) that
// the pipeline stage children use.
// Protocol: payloads/civshim.js header comment + README.md "The civshim wire
// protocol". Companion: tests/civshim-sim.cjs (console-side suite).
// Origin: original — BarbarismJB.
// Run: node tests/protocol-conformance.cjs   (exit 0 = all checks passed)
'use strict';
const net = require('node:net');
const http = require('node:http');
const path = require('node:path');
const assert = require('node:assert');
const {Connection, parseHello} = require('../engine/lib/connection.cjs');
const {serve, Civshim, OP, MAX_STREAM} = require('../engine/lib/bridge.cjs');

const SDK = 0x7100000000n, MAIN = 0x7000000000n, SCRATCH = 0x5000000000n;
const REQUEST_MAGIC = 0x43495631;

// ---- fake console ------------------------------------------------------------
// Speaks the civshim wire protocol with scripted per-op behavior and a
// paged memory model so READ/WRITE round-trips are byte-exact.
function makeHello({magic = 0x31564943, version = 1, platform = 2, reserved = 0,
  main = MAIN, mainSize = 0n, sdk = SDK, sdkSize = 0n, scratch = SCRATCH,
  scratchBytes = 0x1000n, svc = {}, trailer = null} = {}) {
  const header = Buffer.alloc(128);
  header.writeUInt32LE(magic, 0);
  header.writeUInt32LE(version, 4);
  header.writeUInt32LE(platform, 8);
  header.writeUInt32LE(reserved, 12);
  header.writeBigUInt64LE(main, 16);
  header.writeBigUInt64LE(mainSize, 24);
  header.writeBigUInt64LE(sdk, 32);
  header.writeBigUInt64LE(sdkSize, 40);
  header.writeBigUInt64LE(scratch, 48);
  header.writeBigUInt64LE(scratchBytes, 56);
  header.writeBigUInt64LE(BigInt(svc.query_memory ?? 0n), 64);
  header.writeBigUInt64LE(BigInt(svc.send_sync_request ?? 0n), 72);
  header.writeBigUInt64LE(BigInt(svc.connect_to_named_service ?? 0n), 80);
  header.writeBigUInt64LE(BigInt(svc.sleep_thread ?? 0n), 88);
  const json = trailer === null
    ? {svc: {query_memory: null, send_sync_request: null, connect_to_named_service: null, sleep_thread: null},
       sdk_offsets: {longjmp: null, pthread_create: null, pthread_join: null, pthread_exit: null}}
    : trailer;
  const text = Buffer.from(JSON.stringify(json), 'utf8');
  const padded = Buffer.alloc(256);
  text.copy(padded);
  return Buffer.concat([header, padded]);
}

// A scripted console: behavior can be overridden per op or per message via
// the `script` list ({match, reply} canned responses) for error-path tests.
class FakeConsole {
  constructor(options = {}) {
    this.hello = options.hello === undefined ? makeHello(options.helloOverrides || {}) : options.hello;
    this.memory = new Map(); // page -> Buffer(4096)
    this.requests = [];
    this.script = options.script || [];  // (request) => Buffer | null canned wire bytes
    this.dropAfterHello = options.dropAfterHello || false;
    this.server = null; this.port = 0; this.sockets = new Set();
  }
  page(address) {
    const index = Number(address >> 12n);
    let page = this.memory.get(index);
    if (!page) {page = Buffer.alloc(4096); this.memory.set(index, page);}
    return page;
  }
  read(address, length) {const out = Buffer.alloc(Number(length)); for (let i = 0n; i < length; i++) out[Number(i)] = this.page(address + i)[Number((address + i) & 0xfffn)]; return out;}
  write(address, bytes) {for (let i = 0; i < bytes.length; i++) this.page(address + BigInt(i))[Number((address + BigInt(i)) & 0xfffn)] = bytes[i];}
  async start() {
    this.server = net.createServer(socket => this.onSocket(socket));
    await new Promise(resolve => this.server.listen(0, '127.0.0.1', resolve));
    this.port = this.server.address().port;
    return this;
  }
  async stop() {
    for (const socket of this.sockets) socket.destroy();
    await new Promise(resolve => this.server.close(() => resolve()));
  }
  respond(socket, op, id, status, payload = Buffer.alloc(0)) {
    const header = Buffer.alloc(20);
    header.writeUInt32LE(REQUEST_MAGIC, 0);
    header.writeUInt32LE((op | 0x80000000) >>> 0, 4);
    header.writeUInt32LE(id, 8);
    header.writeUInt32LE(payload.length, 12);
    header.writeUInt32LE(status, 16);
    socket.write(Buffer.concat([header, payload]));
  }
  onSocket(socket) {
    this.sockets.add(socket);
    socket.write(this.hello); // the greeting, exactly like payloads/civshim.js
    let buffer = Buffer.alloc(0);
    socket.on('data', bytes => {
      buffer = Buffer.concat([buffer, bytes]);
      if (this.dropAfterHello) return;
      for (;;) {
        if (buffer.length < 16) break;
        const magic = buffer.readUInt32LE(0), op = buffer.readUInt32LE(4);
        const id = buffer.readUInt32LE(8), payloadLen = buffer.readUInt32LE(12);
        if (magic !== REQUEST_MAGIC) {socket.destroy(); return;}
        if (buffer.length < 16 + payloadLen) break;
        const payload = buffer.subarray(16, 16 + payloadLen);
        let rawLen = 0;
        if (op === OP.WRITE) rawLen = Number(payload.readBigUInt64LE(8));
        if (buffer.length < 16 + payloadLen + rawLen) break;   // wait for WRITE raw
        const raw = buffer.subarray(16 + payloadLen, 16 + payloadLen + rawLen);
        buffer = buffer.subarray(16 + payloadLen + rawLen);
        const request = {op, id, payload, raw};
        this.requests.push({op, id, payloadLen});
        for (const line of this.script) {
          const canned = line(request, socket, this);
          if (canned !== null && canned !== undefined) return;
        }
        this.dispatch(socket, request);
      }
    });
    socket.on('error', () => {});
  }
  dispatch(socket, {op, id, payload, raw}) {
    switch (op) {
      case OP.PING: return this.respond(socket, op, id, 0, payload.subarray(0, 32));
      case OP.CALL: {
        const fn = payload.readBigUInt64LE(0), argc = payload.readUInt32LE(8);
        let sum = 0n;
        for (let i = 0; i < argc; i++) sum += payload.readBigUInt64LE(16 + i * 8);
        const out = Buffer.alloc(8);
        out.writeBigUInt64LE(sum === 0n ? fn : sum);
        return this.respond(socket, op, id, 0, out);
      }
      case OP.READ: {
        const address = payload.readBigUInt64LE(0), length = payload.readBigUInt64LE(8);
        const header = Buffer.alloc(20);
        header.writeUInt32LE(REQUEST_MAGIC, 0);
        header.writeUInt32LE((op | 0x80000000) >>> 0, 4);
        header.writeUInt32LE(id, 8);
        header.writeUInt32LE(Number(length), 12);
        header.writeUInt32LE(0, 16);
        socket.write(Buffer.concat([header, this.read(address, length)]));
        return;
      }
      case OP.WRITE: this.write(payload.readBigUInt64LE(0), raw); return this.respond(socket, op, id, 0);
      case OP.QUERY: {
        const out = Buffer.alloc(32);
        out.writeBigUInt64LE(SDK, 0); out.writeBigUInt64LE(0x800000n, 8);
        out.writeBigUInt64LE(3n, 16); out.writeBigUInt64LE(5n, 24);
        return this.respond(socket, op, id, 0, out);
      }
      case OP.ALLOC: {
        const out = Buffer.alloc(8);
        out.writeBigUInt64LE(0x5100000000n + BigInt(this.requests.length * 0x1000));
        return this.respond(socket, op, id, 0, out);
      }
      case OP.FREE: return this.respond(socket, op, id, 0);
      case OP.THREAD_CREATE: {
        const out = Buffer.alloc(8);
        out.writeBigUInt64LE(0x900d0001n);
        return this.respond(socket, op, id, 0, out);
      }
      case OP.THREAD_JOIN: return this.respond(socket, op, id, 0);
      case OP.SLEEP: return this.respond(socket, op, id, 0);
      case OP.UPD_OFFSETS: return this.respond(socket, op, id, 0,
        Buffer.from(JSON.stringify({svc: {query_memory: 4096}, sdk_offsets: {}, modules: {}})));
      default: return this.respond(socket, op, id, 3);
    }
  }
}

// A raw client Connection to a FakeConsole (bypasses connect()'s TCP dialing
// only where a pre-connected socket is needed).
function connectTo(console_) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({host: '127.0.0.1', port: console_.port});
    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });
}

async function main() {
  let passed = 0;
  const step = async (name, body) => {
    try {await body(); passed++; console.log('  ok  ' + name);}
    catch (error) {console.error('  FAIL ' + name + ': ' + error.message); throw error;}
  };

  // -- hello validation ---------------------------------------------------------
  await step('parseHello accepts a well-formed greeting', async () => {
    const hello = parseHello(makeHello().subarray(0, 128), makeHello().subarray(128));
    assert.strictEqual(hello.sdk, Number(SDK));
    assert.strictEqual(hello.main, Number(MAIN));
    assert.strictEqual(hello.scratch, Number(SCRATCH));
    assert.strictEqual(hello.svc.query_memory, 0);
    assert.strictEqual(hello.offsets.svc.query_memory, null);
  });
  for (const [name, overrides] of [
    ['bad magic', {magic: 0x31495643}],
    ['wrong version', {version: 2}],
    ['wrong platform', {platform: 1}],
    ['non-zero reserved word', {reserved: 1}],
    ['implausible main base', {main: 0x10n}],
    ['unaligned sdk base', {sdk: SDK + 3n}],
    ['zero scratch size', {scratchBytes: 0n}],
    ['imprecise (2^53+) address', {main: 1n << 54n}]
  ]) await step('parseHello rejects: ' + name, async () => {
    assert.throws(() => parseHello(makeHello(overrides).subarray(0, 128), makeHello().subarray(128)),
      error => error.code === 'E_PROTOCOL', 'must fail with E_PROTOCOL');
  });
  await step('parseHello rejects a non-JSON trailer', async () => {
    const whole = makeHello();
    whole.subarray(128).fill(0x7b); // "{" everywhere -> invalid JSON
    assert.throws(() => parseHello(whole.subarray(0, 128), whole.subarray(128)),
      error => error.code === 'E_PROTOCOL');
  });

  // -- full-stack round-trips through the real Civshim client --------------------
  const console_ = await new FakeConsole().start();
  try {
    const {connect} = require('../engine/lib/connection.cjs');
    await step('connect(): hello exchange and address validation', async () => {
      const connected = await connect({host: '127.0.0.1', port: console_.port, timeout: 2000});
      assert.strictEqual(connected.addresses.sdk, Number(SDK));
      connected.connection.close();
    });
    await step('connect(): no listener -> coded transport error', async () => {
      const bad = await new FakeConsole().start();
      const port = bad.port; await bad.stop();
      await assert.rejects(async () => require('../engine/lib/connection.cjs')
        .connect({host: '127.0.0.1', port, timeout: 500}),
        error => error.code === 'E_TRANSPORT');
    });

    // One long-lived connection for the op battery.
    const socket = await connectTo(console_);
    const connection = new Connection(socket, 5000);
    const helloHeader = await connection.read(128);   // consume the greeting
    const helloTrailer = await connection.read(256);
    const addresses = parseHello(helloHeader, helloTrailer);
    const civshim = new Civshim(connection, addresses.sdk);

    await step('PING round-trip (incl. 32-byte cap)', async () => {
      const pong = await civshim.request(OP.PING, Buffer.from('conformance-ping'));
      assert.strictEqual(pong.toString(), 'conformance-ping');
      const big = await civshim.request(OP.PING, Buffer.alloc(40, 1));
      assert.strictEqual(big.length, 32);
    });
    await step('CALL round-trip (6 args)', async () => {
      const result = await civshim.call(SDK + 0x50n, [1n, 2n, 3n, 4n, 5n, 6n]);
      assert.strictEqual(result, 21n);
    });
    await step('READ returns exact streamed bytes', async () => {
      const data = Buffer.from(Array.from({length: 4096}, (_, i) => i & 0xff));
      console_.write(SCRATCH, data);
      const back = await civshim.read(Number(SCRATCH), data.length);
      assert.ok(back.equals(data));
    });
    await step('WRITE delivers raw bytes after the frame (byte-exact)', async () => {
      const data = Buffer.from(Array.from({length: 1000}, (_, i) => (i * 13) & 0xff));
      await civshim.write(Number(SCRATCH), data);
      assert.ok(console_.read(SCRATCH, 1000).equals(data));
      assert.strictEqual(console_.requests.at(-1).payloadLen, 16, 'frame payloadLen excludes raw');
    });
    await step('QUERY shape {base,size,type,perm}', async () => {
      const region = await civshim.query(Number(SDK));
      assert.strictEqual(region.address, SDK);
      assert.strictEqual(region.size, 0x800000n);
      assert.strictEqual(region.type, 3);
      assert.strictEqual(region.permissions, 5);
    });
    await step('ALLOC / FREE round-trip', async () => {
      const pointer = await civshim.alloc(0x1000);
      assert.ok(pointer >= 0x5100000000 && pointer < 2 ** 39);
      await civshim.free(pointer);
    });
    await step('THREAD_CREATE / THREAD_JOIN / SLEEP round-trip', async () => {
      const thread = await civshim.threadCreate(SCRATCH);
      assert.strictEqual(thread, 0x900d0001);
      await civshim.threadJoin(thread);
      await civshim.sleep(1n);
    });
    await step('UPD_OFFSETS: JSON upload, merged reply parsed', async () => {
      const merged = await civshim.updateOffsets({svc: {query_memory: 4096}});
      assert.strictEqual(merged.svc.query_memory, 4096);
    });
    await step('serialized queue: concurrent requests all complete in order', async () => {
      const replies = await Promise.all(Array.from({length: 5 }, (_, i) =>
        civshim.request(OP.PING, Buffer.from('sq-' + i))));
      assert.deepStrictEqual(replies.map(reply => reply.toString()),
        ['sq-0', 'sq-1', 'sq-2', 'sq-3', 'sq-4']);
    });
    await step('client-side validation rejects bad arguments without touching the wire', async () => {
      await assert.rejects(async () => civshim.read(0, 16), error => error.code === 'E_ARGS');
      await assert.rejects(async () => civshim.read(Number(SCRATCH), 0), error => error.code === 'E_ARGS');
      await assert.rejects(async () => civshim.read(Number(SCRATCH), MAX_STREAM + 1), error => error.code === 'E_ARGS');
      await assert.rejects(async () => civshim.write(Number(SCRATCH), Buffer.alloc(0)), error => error.code === 'E_ARGS');
      await assert.rejects(async () => civshim.alloc(0), error => error.code === 'E_ARGS');
      await assert.rejects(async () => civshim.alloc(0x50000000), error => error.code === 'E_ARGS');
      await assert.rejects(async () => civshim.call(0n, []), error => error.code === 'E_ARGS');
      await assert.rejects(async () => civshim.call(SDK + 2n, []), error => error.code === 'E_ARGS'); // unaligned
      await assert.rejects(async () => civshim.call(SDK, [1n, 2n, 3n, 4n, 5n, 6n, 7n]), error => error.code === 'E_ARGS');
    });

    // -- error + framing paths ------------------------------------------------------
    await step('console error status surfaces as a coded rejection', async () => {
      const failing = await new FakeConsole({script: [
        (request, socket, fake) => {
          if (request.op !== OP.SLEEP) return null;
          fake.respond(socket, request.op, request.id, 2, Buffer.from('svc SleepThread unavailable'));
          return true;
        }
      ]}).start();
      const socket2 = await connectTo(failing);
      const connection2 = new Connection(socket2, 5000);
      await connection2.read(128); await connection2.read(256);
      const civshim2 = new Civshim(connection2, Number(SDK));
      await assert.rejects(async () => civshim2.sleep(1n),
        error => error.code === 'E_PROTOCOL' && /status 2/.test(error.message));
      connection2.close();
      await failing.stop();
    });
    await step('mismatched response framing is rejected (E_PROTOCOL)', async () => {
      const twisted = await new FakeConsole({script: [
        (request, socket) => {
          if (request.op !== OP.PING) return null;
          const header = Buffer.alloc(20);
          header.writeUInt32LE(REQUEST_MAGIC, 0);
          header.writeUInt32LE((OP.CALL | 0x80000000) >>> 0, 4);  // wrong op echo
          header.writeUInt32LE(request.id, 8);
          header.writeUInt32LE(0, 12);
          header.writeUInt32LE(0, 16);
          socket.write(header);
          return true;
        }
      ]}).start();
      const socket3 = await connectTo(twisted);
      const connection3 = new Connection(socket3, 5000);
      await connection3.read(128); await connection3.read(256);
      const civshim3 = new Civshim(connection3, Number(SDK));
      await assert.rejects(async () => civshim3.request(OP.PING), error => error.code === 'E_PROTOCOL');
      connection3.close();
      await twisted.stop();
    });
    await step('oversized declared response length is rejected', async () => {
      const liar = await new FakeConsole({script: [
        (request, socket) => {
          if (request.op !== OP.PING) return null;
          const header = Buffer.alloc(20);
          header.writeUInt32LE(REQUEST_MAGIC, 0);
          header.writeUInt32LE((request.op | 0x80000000) >>> 0, 4);
          header.writeUInt32LE(request.id, 8);
          header.writeUInt32LE(0x900000, 12);   // beyond the bridge stream cap
          header.writeUInt32LE(0, 16);
          socket.write(header);
          return true;
        }
      ]}).start();
      const socket4 = await connectTo(liar);
      const connection4 = new Connection(socket4, 5000);
      await connection4.read(128); await connection4.read(256);
      const civshim4 = new Civshim(connection4, Number(SDK));
      await assert.rejects(async () => civshim4.request(OP.PING), error => error.code === 'E_PROTOCOL');
      connection4.close();
      await liar.stop();
    });
    await step('coalesced responses: both frames resolve from one TCP segment', async () => {
      const burst = await new FakeConsole({script: [
        (request, socket, fake) => {
          if (request.op !== OP.PING || request.id !== 1) return null;
          fake.respond(socket, request.op, request.id, 0, Buffer.from('r1'));
          const header = Buffer.alloc(20);      // pre-write the NEXT response
          header.writeUInt32LE(REQUEST_MAGIC, 0);
          header.writeUInt32LE((request.op | 0x80000000) >>> 0, 4);
          header.writeUInt32LE(2, 8);           // id 2
          header.writeUInt32LE(2, 12);          // payload "r2"
          header.writeUInt32LE(0, 16);
          socket.write(Buffer.concat([header, Buffer.from('r2')]));
          return true;
        }
      ]}).start();
      const socket5 = await connectTo(burst);
      const connection5 = new Connection(socket5, 5000);
      await connection5.read(128); await connection5.read(256);
      const civshim5 = new Civshim(connection5, Number(SDK));
      const first = await civshim5.request(OP.PING, Buffer.alloc(0));
      assert.strictEqual(first.toString(), 'r1');
      // The second response is already buffered behind the first — the next
      // request must pair with it (ids are serialized, so request 2 gets r2).
      const second = await civshim5.request(OP.PING, Buffer.alloc(0));
      assert.ok(second.length === 2, 'second response resolved from buffered bytes');
      connection5.close();
      await burst.stop();
    });
    await step('response timeout: E_TIMEOUT and the connection dies (never replay)', async () => {
      const silent = await new FakeConsole({script: [() => true]}).start(); // swallow everything
      const socket6 = await connectTo(silent);
      const connection6 = new Connection(socket6, 250);
      await connection6.read(128); await connection6.read(256);
      const civshim6 = new Civshim(connection6, Number(SDK));
      await assert.rejects(async () => civshim6.request(OP.PING),
        error => error.code === 'E_TIMEOUT' || error.code === 'E_TRANSPORT');
      await assert.rejects(async () => civshim6.request(OP.PING), () => true, 'connection poisoned');
      connection6.close();
      await silent.stop();
    });

    // -- loopback HTTP bridge (pipeline child front end) ---------------------------
    await step('serve(): status/call/read/write/alloc over loopback HTTP', async () => {
      const socket7 = await connectTo(console_);
      const connection7 = new Connection(socket7, 5000);
      await connection7.read(128); await connection7.read(256);
      const bridge = await serve({connection: connection7, addresses});
      const call = body => new Promise((resolve, reject) => {
        const request = http.request({host: '127.0.0.1', port: bridge.port, method: 'POST', path: '/'},
          response => {
            const parts = [];
            response.on('data', part => parts.push(part));
            response.on('end', () => {
              const parsed = JSON.parse(Buffer.concat(parts));
              response.statusCode === 200 ? resolve(parsed) : reject(Error(parsed.error));
            });
          });
        request.end(JSON.stringify(body));
      });
      const status = await call({command: 'status'});
      assert.strictEqual(status.ready, true);
      const sum = await call({command: 'call-address', address: String(SDK + 0x50n), args: [5, 6]});
      assert.strictEqual(sum.result, '11');
      const data = Buffer.from('bridge-write-payload');
      await call({command: 'write', address: Number(SCRATCH), data: data.toString('base64')});
      const read = await call({command: 'read', address: Number(SCRATCH), length: data.length});
      assert.ok(Buffer.from(read.data, 'base64').equals(data));
      const allocation = await call({command: 'alloc', size: 4096});
      assert.ok(allocation.address > 0);
      await call({command: 'free', address: allocation.address});
      await assert.rejects(async () => call({command: 'read', address: 0, length: 8}), /plausible guest address/);
      await assert.rejects(async () => call({command: 'write', address: Number(SCRATCH), data: ''}), /write payload/);
      await assert.rejects(async () => call({command: 'no-such-command'}), /Unknown bridge command/);
      await bridge.close();
    });

    connection.close();
  } finally {
    await console_.stop();
  }

  console.log('protocol-conformance: ' + passed + ' checks passed');
  return 0;
}

if (require.main === module)
  main().then(() => process.exit(0), error => {console.error('protocol-conformance: FAILED: ' + error.message); process.exit(1);});
module.exports = {main};
