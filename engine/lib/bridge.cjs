// engine/lib/bridge.cjs — civshim client + loopback HTTP bridge for the
// pipeline stage children.
//
// Purpose: (1) Civshim — one serialized client for the console-facing binary
// protocol (the host CONNECTS to the console's :39381 listener); (2) serve() —
// a loopback HTTP front so the battle-tested ns2jb stage programs (pipeline
// children using shared/rpc.cjs) stay byte-identical to upstream. The
// translated command set is a superset of the old SmileBASIC bridge: 'alloc',
// 'free', 'thread-create', 'thread-join', 'sleep', 'upd-offsets' back the app
// session and the ropchain worker backend.
// Protocol: payloads/civshim.js header comment + README.md "The civshim wire
// protocol". Discipline (unchanged from ns2jb): one in-flight request at a
// time; a timeout or socket error permanently fails the connection because a
// native operation may already have completed — never replay, 180 s budget.
// Errors carry E_PROTOCOL / E_ARGS / E_VERIFY codes from shared/errors.cjs.
// Origin: ported from ns2jb engine/lib/bridge.cjs (SmileBASIC loopback-native
// bridge), heavily adapted for BarbarismJB — see `// barbarism:` markers.
const http = require('node:http');
const {fail} = require('../shared/errors.cjs');

const OP = {PING: 1, CALL: 2, READ: 3, WRITE: 4, QUERY: 5, ALLOC: 6, FREE: 7,
  THREAD_CREATE: 8, THREAD_JOIN: 9, SLEEP: 10, UPD_OFFSETS: 11,
  THREAD_CREATE_RAW: 12, THREAD_WAIT: 13, THREAD_CLOSE: 14, THREAD_SCHED_BORROW: 15};
const REQUEST_MAGIC = 0x43495631; // wire bytes read "1VIC"
const RESPONSE_BYTES = 20;        // magic, op|0x80000000, id, payloadLen, status
const MAX_STREAM = 0x80000;       // one civshim READ/WRITE per bridge request
const MAX_PAYLOAD = 0x10000;      // civshim request payload (framed) cap
const MIN_ADDRESS = 0x1000;       // below this no mapping ever exists
const MAX_ADDRESS = 2 ** 47;      // Switch 2 userland never reaches here

function u64le(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(BigInt.asUintN(64, BigInt(value)));
  return bytes;
}

function exactInteger(value, what) {
  const number = typeof value === 'bigint' ? value :
    typeof value === 'number' && Number.isSafeInteger(value) ? BigInt(value) :
    typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value) ? BigInt(value) : null;
  if (number === null || number < 0n || number > 0xffffffffffffffffn)
    throw fail('E_ARGS', 'Invalid ' + what + '; use exact integers (BigInt for values above 2^53)');
  return number;
}

// Plausible guest address (page-aligned mappings start at 0x1000; Switch 2
// userland stays far below 2^47). Catches host-side argument bugs before they
// become console crashes.
function guestAddress(value, what) {
  const number = exactInteger(value, what);
  if (number < BigInt(MIN_ADDRESS) || number >= BigInt(MAX_ADDRESS))
    throw fail('E_ARGS', 'Invalid ' + what + ' 0x' + number.toString(16) +
      ' — outside plausible guest memory (0x1000..2^47)');
  return number;
}

function hostAddress(value, what) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < MIN_ADDRESS || number >= MAX_ADDRESS)
    throw fail('E_ARGS', 'Invalid ' + what + '; expected a plausible guest address as a Number');
  return number;
}

// One serialized civshim connection. Every request goes through enqueue(); a
// failure poisons the connection and every later request rejects.
class Civshim {
  constructor(connection, sdk) {
    this.connection = connection;
    this.sdk = sdk; // absolute SDK base from the CIV1 hello (sdk-relative call offsets)
    this.queue = Promise.resolve();
    this.calls = 0;
    this.nextId = 1;
  }

  enqueue(task) {
    const result = this.queue.then(task, () => task());
    this.queue = result.catch(() => {});
    return result;
  }

  request(op, payload = Buffer.alloc(0), raw = Buffer.alloc(0)) {
    return this.enqueue(async () => {
      if (!Buffer.isBuffer(payload) || payload.length > MAX_PAYLOAD)
        throw fail('E_ARGS', 'civshim request payload exceeds ' + MAX_PAYLOAD + ' bytes');
      if (raw.length && op !== OP.WRITE) throw fail('E_ARGS', 'Raw stream bytes are only valid on WRITE');
      if (raw.length > MAX_STREAM) throw fail('E_ARGS', 'civshim raw stream exceeds the bridge cap');
      const id = this.nextId++ & 0xffffffff;
      const header = Buffer.alloc(16);
      header.writeUInt32LE(REQUEST_MAGIC, 0);
      header.writeUInt32LE(op, 4);
      header.writeUInt32LE(id, 8);
      // The frame's payloadLen covers only `payload`. `raw` (WRITE data) is
      // sent after the frame and lands in console memory via civshim's
      // zero-copy recv loop — it must NOT be counted here or civshim would
      // buffer it through JS.
      header.writeUInt32LE(payload.length, 12);
      await this.connection.write(Buffer.concat([header, payload, raw]));
      const response = await this.connection.read(RESPONSE_BYTES);
      if (response.length !== RESPONSE_BYTES ||
          response.readUInt32LE() !== REQUEST_MAGIC ||
          (response.readUInt32LE(4) >>> 0) !== ((op | 0x80000000) >>> 0) ||
          response.readUInt32LE(8) !== id)
        throw fail('E_PROTOCOL', 'civshim response framing mismatch');
      const status = response.readUInt32LE(16);
      const length = response.readUInt32LE(12);
      if (length > MAX_STREAM) throw fail('E_PROTOCOL', 'civshim response exceeds the bridge stream cap');
      const bytes = length ? await this.connection.read(length) : Buffer.alloc(0);
      if (bytes.length !== length) throw fail('E_PROTOCOL', 'civshim response payload was short');
      if (status !== 0) throw fail('E_PROTOCOL', 'civshim op ' + op + ' failed (status ' + status + '): ' + bytes.toString('utf8'));
      this.calls++;
      return bytes;
    });
  }

  call(address, args) {
    if (!Array.isArray(args) || args.length > 6) throw fail('E_ARGS', 'At most six native arguments are supported');
    const target = exactInteger(address, 'native function address');
    if (target === 0n || target % 4n !== 0n)
      throw fail('E_ARGS', 'Native call target must be a non-zero 4-aligned address');
    const payload = Buffer.concat([u64le(target), (() => {
      const bytes = Buffer.alloc(8);
      bytes.writeUInt32LE(args.length);
      return bytes; // u32 argc + u32 reserved
    })(), Buffer.concat(args.map(argument => u64le(exactInteger(argument, 'native argument'))))]);
    return this.request(OP.CALL, payload).then(bytes => {
      if (bytes.length !== 8) throw fail('E_PROTOCOL', 'civshim CALL reply is not 8 bytes');
      return bytes.readBigUInt64LE();
    });
  }

  read(address, length) {
    hostAddress(address, 'civshim read address');
    if (!Number.isInteger(length) || length < 1 || length > MAX_STREAM)
      throw fail('E_ARGS', 'Invalid civshim read span');
    return this.request(OP.READ, Buffer.concat([u64le(address), u64le(length)]));
  }

  write(address, bytes) {
    hostAddress(address, 'civshim write address');
    if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_STREAM)
      throw fail('E_ARGS', 'Invalid civshim write span');
    return this.request(OP.WRITE, Buffer.concat([u64le(address), u64le(bytes.length)]), bytes);
  }

  query(address) {
    hostAddress(address, 'civshim query address');
    return this.request(OP.QUERY, u64le(address)).then(bytes => {
      if (bytes.length !== 32) throw fail('E_PROTOCOL', 'civshim QUERY reply is not 32 bytes');
      // civshim returns 4x u64 {base, size, type, perm}; the attributes and
      // reference counts are not part of the civshim contract (see README.md
      // — ipcReference-based guards see zero).
      return {
        address: bytes.readBigUInt64LE(), size: bytes.readBigUInt64LE(8),
        type: Number(bytes.readBigUInt64LE(16)), permissions: Number(bytes.readBigUInt64LE(24)),
        attributes: 0, ipcReferences: 0, deviceReferences: 0
      };
    });
  }

  alloc(size) {
    if (!Number.isSafeInteger(size) || size < 1 || size > 0x40000000) throw fail('E_ARGS', 'Invalid allocation size');
    return this.request(OP.ALLOC, u64le(size)).then(bytes => {
      if (bytes.length !== 8) throw fail('E_PROTOCOL', 'civshim ALLOC reply is not 8 bytes');
      return Number(bytes.readBigUInt64LE());
    });
  }

  free(address) {
    return this.request(OP.FREE, u64le(guestAddress(address, 'free address')));
  }

  // barbarism: THREAD_CREATE payload is exactly { u64 jbPtr } — the pthread
  // library allocates the worker stack (attr = NULL), so no stack top exists.
  threadCreate(jbPtr) {
    return this.request(OP.THREAD_CREATE, u64le(guestAddress(jbPtr, 'jmp_buf pointer')))
      .then(bytes => {
        if (bytes.length !== 8) throw fail('E_PROTOCOL', 'civshim THREAD_CREATE reply is not 8 bytes');
        return Number(bytes.readBigUInt64LE());
      });
  }

  threadJoin(thread) {
    return this.request(OP.THREAD_JOIN, u64le(guestAddress(thread, 'thread handle')));
  }

  // barbarism: raw-svc thread surface (civswitch-kit hardware recipe — see
  // payloads/civshim.js ops 12-15 and docs/CIVSWITCH-INTEGRATION.md §2c).
  // Raw kernel-thread creation: nn::os::CreateThread hangs and pthread_create
  // silently no-ops on Civ 7 1.0.0, so wave workers enter via
  // svcCreateThread(entry=longjmp, arg=jbPtr, stackTop, priority, core).
  // Resolves {handle, createResult, startResult}: handle non-zero = live
  // thread; createResult 0xE001 means the kernel rejected priority/core —
  // retry another borrowed core.
  threadCreateRaw(jbPtr, stackTop, priority, core) {
    const payload = Buffer.concat([
      u64le(guestAddress(jbPtr, 'raw-thread jmp_buf pointer')),
      u64le(guestAddress(stackTop, 'raw-thread stack top')),
      (() => {const b = Buffer.alloc(8); b.writeUInt32LE(priority); b.writeUInt32LE(core, 4); return b;})()
    ]);
    return this.request(OP.THREAD_CREATE_RAW, payload).then(bytes => {
      if (bytes.length !== 24) throw fail('E_PROTOCOL', 'civshim THREAD_CREATE_RAW reply is not 24 bytes');
      return {
        handle: Number(bytes.readBigUInt64LE()),
        createResult: Number(bytes.readBigUInt64LE(8)),
        startResult: Number(bytes.readBigUInt64LE(16))
      };
    });
  }

  // Single-shot svcWaitSynchronization on one handle; the host drives the
  // poll loop. Resolves {result, index}: result 0 = signaled, 0xEA01 (59905)
  // = kernel wait timeout — poll again; other codes are the caller's to judge.
  threadWait(handle, timeoutNs = 0) {
    const payload = Buffer.concat([u64le(handle), u64le(exactInteger(timeoutNs, 'wait timeout'))]);
    return this.request(OP.THREAD_WAIT, payload).then(bytes => {
      if (bytes.length !== 16) throw fail('E_PROTOCOL', 'civshim THREAD_WAIT reply is not 16 bytes');
      return {result: Number(bytes.readBigUInt64LE()), index: Number(bytes.readBigUInt64LE(8))};
    });
  }

  threadClose(handle) {
    return this.request(OP.THREAD_CLOSE, u64le(exactInteger(handle, 'raw thread handle')))
      .then(bytes => {
        if (bytes.length !== 8) throw fail('E_PROTOCOL', 'civshim THREAD_CLOSE reply is not 8 bytes');
        return Number(bytes.readBigUInt64LE());
      });
  }

  // Borrow a valid priority + usable-core mask from a live game thread via
  // the on-console nn::os manager-list walk. Resolves
  // {priority, coreMask, manager, nodes}.
  threadSchedBorrow() {
    return this.request(OP.THREAD_SCHED_BORROW).then(bytes => {
      if (bytes.length !== 32) throw fail('E_PROTOCOL', 'civshim THREAD_SCHED_BORROW reply is not 32 bytes');
      return {
        priority: Number(bytes.readBigUInt64LE()),
        coreMask: bytes.readBigUInt64LE(8),
        manager: Number(bytes.readBigUInt64LE(16)),
        nodes: Number(bytes.readBigUInt64LE(24))
      };
    });
  }

  sleep(nanoseconds) {
    return this.request(OP.SLEEP, u64le(exactInteger(nanoseconds, 'sleep duration')));
  }

  // barbarism: op 11 — upload the offsets groups the console consumes (svc,
  // sdk_offsets, modules sizes) so a shim baked with an empty dict gets
  // QUERY/SLEEP/THREAD_* live without a redeploy. Persists console-side for
  // the session; returns the console's merged dict.
  async updateOffsets(dict) {
    const upload = {};
    for (const group of ['svc', 'sdk_offsets', 'modules']) {
      const entries = dict?.[group];
      if (entries === undefined || entries === null) continue;
      if (!entries || typeof entries !== 'object' || Array.isArray(entries))
        throw fail('E_ARGS', 'civshim offsets group "' + group + '" is not an object');
      upload[group] = entries;
    }
    if (!Object.keys(upload).length) throw fail('E_ARGS', 'updateOffsets received no usable groups');
    const serialized = Buffer.from(JSON.stringify(upload), 'utf8');
    if (serialized.length > MAX_PAYLOAD) throw fail('E_ARGS', 'updateOffsets payload exceeds ' + MAX_PAYLOAD + ' bytes');
    const bytes = await this.request(OP.UPD_OFFSETS, serialized);
    let merged;
    try {merged = JSON.parse(bytes.toString('utf8'));}
    catch {throw fail('E_PROTOCOL', 'civshim UPD_OFFSETS reply is not valid JSON');}
    return merged;
  }
}

// Stage programs share one native connection through this local, serialized
// bridge. Its address exists only in the current launch directory.
async function serve(connected) {
  // barbarism: connected = {connection, addresses} from lib/connection.cjs.
  const civshim = new Civshim(connected.connection, connected.addresses.sdk);
  const verified = new Set();
  let queue = Promise.resolve();
  const enqueue = task => {
    const result = queue.then(task);
    queue = result.catch(() => {});
    return result;
  };
  async function handle(request) {
    const {command} = request;
    if (command === 'status') return {ready: !connected.connection.error, calls: civshim.calls};
    if (command === 'call') {
      // SDK-relative call kept for ns2jb stage compatibility (app/rpc.cjs).
      const offset = exactInteger(request.offset, 'SDK offset');
      if (offset < 0 || offset >= 2 ** 31) throw fail('E_ARGS', 'Invalid SDK function offset');
      const result = await civshim.call(BigInt(civshim.sdk) + offset, request.args || []);
      return {result: result.toString(), output: ''};
    }
    if (command === 'call-address') {
      const address = exactInteger(request.address, 'native address');
      const result = await civshim.call(address, request.args || []);
      return {result: result.toString(), output: ''};
    }
    if (command === 'verify-function') {
      if (typeof request.hex !== 'string' || !/^(?:[0-9a-f]{2}){4,256}$/i.test(request.hex))
        throw fail('E_ARGS', 'Expected original native instruction bytes');
      const address = exactInteger(request.address, 'native address');
      // barbarism: verification is host-side now — the console has no scratch
      // echo channel, so the bytes come back over the zero-copy READ path.
      const expected = Buffer.from(request.hex, 'hex');
      const bytes = await civshim.read(Number(address), expected.length);
      if (!bytes.equals(expected)) throw fail('E_VERIFY', 'Native function mapping or instructions differ');
      verified.add(address.toString());
      return {verified: true};
    }
    if (command === 'pair') {
      // barbarism: SmileBASIC paired two calls per packet; the calls are simply
      // issued in order (identical semantics, no atomicity was ever needed).
      if (!Array.isArray(request.calls) || request.calls.length < 1 || request.calls.length > 2)
        throw fail('E_ARGS', 'Native pair must contain one or two calls');
      const results = [];
      for (const item of request.calls) {
        const offset = exactInteger(item.offset, 'SDK offset');
        results.push(await civshim.call(BigInt(civshim.sdk) + offset, item.args || []));
      }
      return {results: results.map(String), output: ''};
    }
    if (command === 'read') {
      hostAddress(request.address, 'read address');
      if (!Number.isInteger(request.length) || request.length < 1 || request.length > MAX_STREAM)
        throw fail('E_ARGS', 'Invalid read span');
      return {data: (await civshim.read(request.address, request.length)).toString('base64')};
    }
    if (command === 'write') {
      hostAddress(request.address, 'write address');
      const bytes = Buffer.from(request.data || '', 'base64');
      if (bytes.length < 1 || bytes.length > 4 * MAX_STREAM)
        throw fail('E_ARGS', 'Invalid write payload size');
      for (let at = 0; at < bytes.length; at += 0x80000) {
        // barbarism: 0x80000-chunked, matching shared/rpc.cjs, so each WRITE fits
        // one civshim frame.
        await civshim.write(request.address + at, bytes.subarray(at, at + 0x80000));
      }
      return {written: true};
    }
    if (command === 'query') return civshim.query(request.address);
    if (command === 'alloc') {
      if (!Number.isSafeInteger(request.size) || request.size < 1 || request.size > 0x40000000)
        throw fail('E_ARGS', 'Invalid allocation size');
      return {address: await civshim.alloc(request.size)};
    }
    if (command === 'free') {await civshim.free(request.address); return {freed: true};}
    if (command === 'thread-create')
      return {thread: await civshim.threadCreate(request.jbPtr)};
    if (command === 'thread-join') {await civshim.threadJoin(request.thread); return {joined: true};}
    if (command === 'thread-create-raw')
      return await civshim.threadCreateRaw(request.jbPtr, request.stackTop, request.priority, request.core);
    if (command === 'thread-wait')
      return await civshim.threadWait(request.thread, request.timeoutNs || 0);
    if (command === 'thread-close')
      return {result: await civshim.threadClose(request.thread)};
    if (command === 'thread-sched-borrow')
      return await civshim.threadSchedBorrow();
    if (command === 'sleep') {await civshim.sleep(request.ns); return {slept: true};}
    if (command === 'upd-offsets') return {merged: await civshim.updateOffsets(request.dict)};
    throw fail('E_ARGS', 'Unknown bridge command');
  }
  const server = http.createServer(async (req, res) => {
    if (req.method !== 'POST' || req.url !== '/') {
      res.writeHead(403).end(); return;
    }
    try {
      const parts = [];
      let length = 0;
      for await (const part of req) {
        length += part.length;
        if (length > 2 * 1024 * 1024) throw Error('Bridge request is too large');
        parts.push(part);
      }
      const request = JSON.parse(Buffer.concat(parts));
      const result = await enqueue(() => handle(request));
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(result, (_, value) => typeof value === 'bigint' ? value.toString() : value));
    } catch (error) {
      res.writeHead(400, {'Content-Type': 'application/json'}).end(JSON.stringify({error: error.message}));
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  // barbarism: the SmileBASIC 5-second keep-awake heartbeat is gone — the Civ 7
  // Gameface process stays foreground on its own (DESIGN.md section 5).
  return {
    port: server.address().port,
    civshim,
    async close() {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
      await queue;
      connected.connection.close();
    },
  };
}

module.exports = {serve, Civshim, OP, MAX_STREAM, MAX_PAYLOAD};
