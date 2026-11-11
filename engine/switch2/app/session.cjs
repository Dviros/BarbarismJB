// engine/switch2/app/session.cjs — own allocations, handles, and raw IPC for
// the freshly paired Civ 7 application process.
//
// barbarism: Rewired from the SmileBASIC SDK layer to civshim ops (see payloads/civshim.js):
//   - initialize:      SDK allocate  -> civshim ALLOC (game calloc) + QUERY validation
//   - openService:     SDK getService -> TIPC over sm: obtained once with
//                      svcConnectToNamedService (logic ported from ns2jb
//                      engine/switch2/ro/control.cjs 'sm-service', proven on 23.0.1)
//   - ipc:             SDK send      -> CALL on the svcSendSyncRequest wrapper
//                      (Switch 2 signature: x0 = message buffer, x1 = size, x2 = handle)
//   - close/free:      svc CloseHandle wrapper / civshim FREE
// The CMIF framing (shared/ipc.cjs) and the serialized session bookkeeping are
// unchanged from ns2jb. All addresses come from the CIV1 hello + offsets
// table (engine/lib/offsets.cjs); nothing SmileBASIC-specific remains here.
const fs = require('node:fs/promises');
const path = require('node:path');
const {client, live} = require('./rpc.cjs');
const transport = require('../../shared/rpc.cjs');
const {packet, response} = require("../../shared/ipc.cjs");
const u32 = value => {const b = Buffer.alloc(4); b.writeUInt32LE(value); return b;};
const u64 = value => {const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(value)); return b;};
const check = (condition, message) => {if (!condition) throw Error(message);};

const result32 = value => Number(BigInt.asUintN(32, BigInt(value)));

class Session {
  constructor(label, bytes = 0x10000) {
    this.label = label;
    this.handles = new Set();
    this.threads = new Set();
    this.base = 0;
    this.bytes = bytes;
    this.log = path.join(__dirname, label + '-events.jsonl');
    this.sm = 0;
  }
  async record(entry) {
    await fs.appendFile(this.log, JSON.stringify({at: new Date().toISOString(), ...entry}) + '\n', {mode: 0o600});
  }
  async verifyCode(expected, label = 'SDK helper') {
    // barbarism: instruction pins are data-driven. A bytes entry is compared
    // fail-loudly (this is how SmileBASIC-table entries must be re-pinned for
    // Civ 7 from the M0 dump); the mapping itself just needs a sane mapping.
    const address = live.sdk + expected.offset, size = expected.bytes.length / 2;
    const region = await this.rpc.query(address);
    check(!region.result && region.permissions === 5 && region.address <= address &&
      address + size <= region.address + region.size, 'Code is not in the current executable mapping');
    const file = path.join(__dirname, 'verified-instructions.json');
    if (!this.codeCache) {
      let cached;
      try {cached = JSON.parse(await fs.readFile(file, 'utf8'));}
      catch (error) {if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;}
      this.codeCache = cached?.session === live.session && cached.sdk === live.sdk ? cached :
        {session: live.session, sdk: live.sdk, code: {}};
    }
    if (this.codeCache.code[expected.offset] === expected.bytes) return;
    check((await this.read(address, size)).toString('hex') === expected.bytes, label + ' instructions differ');
    this.codeCache.code[expected.offset] = expected.bytes;
    await fs.writeFile(file, JSON.stringify(this.codeCache, null, 2) + '\n', {mode: 0o600});
  }
  async ready() {
    return live.platform === 2 && (await transport.request({command: 'status'})).ready;
  }
  // barbarism: logical call names mapped to civshim-resolvable addresses. 'send'
  // and 'close' are the raw svc wrappers from offsets/civ7-100.json; 'memset'
  // is optional (initialize falls back to explicit zero writes); 'free' is a
  // civshim op, not a native call.
  call(name, ...args) {
    if (name === 'send') return this.rpc.call3(live.svc.send_sync_request, ...args);
    if (name === 'close') return this.rpc.call3(live.svc.close_handle, ...args);
    if (name === 'free')
      return transport.request({command: 'free', address: args[0]}).then(() => 0);
    if (name === 'memset') {
      check(live.sdkFn.memset, 'sdk_offsets.memset is absent from offsets/civ7-100.json');
      return this.rpc.call3(live.sdkFn.memset, ...args);
    }
    throw Error('No BarbarismJB mapping for SDK function name: ' + name);
  }
  read(address, bytes) {return this.rpc.read(address, bytes);}
  // Callers must wait for any IPC operation touching this range to finish.
  async readOwned(address, bytes) {
    check(this.base && Number.isInteger(bytes) && bytes > 0 && bytes <= 524288 &&
      Number.isSafeInteger(address) && address >= this.base && address + bytes <= this.base + this.bytes,
      'Owned read is outside the verified allocation');
    return this.rpc.read(address, bytes);
  }
  write(address, bytes) {
    if (this.bulkUploads && bytes.length >= 4096 && this.base && address >= this.base &&
        address + bytes.length <= this.base + this.bytes) return require("./bulk-transfer.cjs").write(this, address, bytes);
    return this.rpc.write(address, bytes);
  }
  async initialize() {
    check(await this.ready(), 'Switch 2 application connection is not ready');
    this.rpc = await client();
    // barbarism: the allocation comes from the game's own heap through civshim
    // ALLOC. The SmileBASIC SDK allocate/getService wrappers and their
    // instruction pins do not exist in the Civ 7 process.
    const reply = await transport.request({command: 'alloc', size: this.bytes});
    this.base = Number(reply.address);
    check(Number.isSafeInteger(this.base) && this.base > 0 && this.base % 4096 === 0, 'Invalid allocation');
    const allocated = await this.rpc.query(this.base);
    check(!allocated.result && allocated.type === 5 && allocated.permissions === 3 &&
      !allocated.attributes && Number(BigInt(allocated.address) + BigInt(allocated.size)) >= this.base + this.bytes,
      'New allocation is not ordinary owned memory');
    if (live.sdkFn.memset) {
      await this.call('memset', this.base, 0, this.bytes);
    } else {
      // No memset pin yet: zero the allocation through the zero-copy WRITE
      // path. Slower, but never wrong.
      const zero = Buffer.alloc(0x80000);
      for (let at = 0; at < this.bytes; at += 0x80000)
        await this.rpc.write(this.base + at, zero.subarray(0, Math.min(0x80000, this.bytes - at)));
    }
    await this.record({operation: 'initialize', session: live.session, base: this.base, bytes: this.bytes});
  }
  // barbarism: obtain the sm: session once with the raw svc wrapper, then every
  // service open is a TIPC GetService on it. Byte format and reply parsing are
  // ported verbatim from ns2jb ro/control.cjs command 'sm-service' (hardware
  // proven on 23.0.1): request {u32 0x11, u32 2, name at +8}; TIPC reply with
  // the domain-object extension.
  async smSession() {
    if (this.sm) return this.sm;
    const stage = this.base + 0x800;
    const name = Buffer.alloc(16);
    Buffer.from('sm:', 'ascii').copy(name);
    await this.write(stage, name);
    const handle = result32(await this.rpc.call3(live.svc.connect_to_named_service, stage, 3, 0));
    check(handle > 0 && handle < 0xffff8000, 'svcConnectToNamedService("sm:") failed: 0x' + handle.toString(16));
    this.sm = handle;
    this.handles.add(handle);
    await this.record({operation: 'ConnectToNamedService', name: 'sm:', handle});
    return handle;
  }
  async openService(name) {
    check(name.length > 0 && name.length <= 8, 'Invalid service name');
    const sm = await this.smSession();
    const bytes = Buffer.alloc(256);
    bytes.writeUInt32LE(0x11);
    bytes.writeUInt32LE(2, 4);
    bytes.write(name, 8);
    await this.write(this.base, bytes);
    const sendResult = result32(await this.call('send', this.base, 4096, sm));
    await this.record({operation: 'sm GetService', name, transport: sendResult});
    check(!sendResult, 'sm: transport failed: 0x' + sendResult.toString(16));
    const raw = await this.readOwned(this.base, 256);
    const first = raw.readUInt32LE(), second = raw.readUInt32LE(4);
    check((first >>> 16) === 0 && (second & 0x3ff) >= 1, 'Unexpected TIPC response descriptors');
    let at = 8;
    const copies = [], moves = [];
    if (second >>> 31) {
      const special = raw.readUInt32LE(at); at += 4;
      check(!(special & 1), 'Unexpected TIPC reply PID');
      for (let i = 0; i < (special >>> 1 & 15); i++, at += 4) copies.push(raw.readUInt32LE(at));
      for (let i = 0; i < (special >>> 5 & 15); i++, at += 4) moves.push(raw.readUInt32LE(at));
    }
    const result = raw.readUInt32LE(at);
    await this.record({operation: 'sm GetService reply', name, result, copies, moves});
    check(!result, 'Service unavailable: ' + name + ' (0x' + (result & 0x3fffff).toString(16) + ')');
    check(!copies.length && moves.length === 1, 'SM did not return one moved service handle');
    const handle = moves[0];
    check(handle > 0 && handle < 0xffff8000, 'Invalid service handle: ' + name);
    this.handles.add(handle);
    return handle;
  }
  async ipc(label, handle, command, data = Buffer.alloc(0), options = {}) {
    await this.write(this.base, packet(command, data, options));
    // barbarism: Switch 2 svcSendSyncRequest carries the message buffer and its
    // size explicitly (x0 = buffer, x1 = size, x2 = session handle) — this is
    // what makes worker-thread IPC from arbitrary staged buffers possible.
    const transportResult = result32(await this.call('send', this.base, 4096, handle));
    await this.record({operation: label, handle, command, transport: transportResult});
    check(!transportResult, label + ': transport 0x' + transportResult.toString(16));
    const raw = await this.readOwned(this.base, 256);
    const reply = response(raw);
    reply.interfaceId = raw.readUInt32LE(raw.length - reply.data.length - 4);
    for (const child of [...reply.copies, ...reply.moves]) this.handles.add(child);
    await this.record({operation: label + ' reply', result: reply.result, copies: reply.copies,
      moves: reply.moves, interfaceId: reply.interfaceId,
      data: reply.data.subarray(0, 32).toString('hex')});
    return reply;
  }
  async close(handle) {
    check(this.handles.has(handle), 'Handle is not owned');
    const result = result32(await this.call('close', handle, 0, 0));
    await this.record({operation: 'CloseHandle', handle, result});
    check(!result, 'Owned handle did not close');
    this.handles.delete(handle);
    if (this.sm === handle) this.sm = 0;
  }
  async closeUpload() {}
  async cleanup() {
    await this.closeUpload();
    if (!await this.ready() || this.threads.size) {
      await this.record({operation: 'cleanupDeferred', base: this.base,
        handles: [...this.handles], threads: [...this.threads]});
      return;
    }
    for (const handle of [...this.handles].reverse()) await this.close(handle);
    if (this.base) {
      await this.call('free', this.base, 0, 0);
      await this.record({operation: 'Free', base: this.base});
      this.base = 0;
    }
  }
}

module.exports = {Session, live, u32, u64, check};
