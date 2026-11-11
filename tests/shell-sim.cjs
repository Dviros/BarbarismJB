// tests/shell-sim.cjs — offline simulation of the BarbarismJB shell (M5).
//
// Purpose: verify engine/lib/shell.cjs and engine/lib/shell-server.cjs against
// injected fakes — no console, no memory endpoint, no RO payload. Checks:
// command dispatch across the whole table, coded argument-validation errors
// (E_ARGS), disconnected-subsystem behavior (E_CONFIG naming the missing
// stage/port), game-memory read/write + hex-dump correctness, malloc/free
// bookkeeping, put/get/save chunking (0x10000) and bis-get chunking (0x4000)
// with sha256 verification, the RO proc-read bulk (0x524F0016) and fallback
// (0x524F0011) paths, proc-patch compare-and-swap semantics, exec-map result
// handling, and the server front (serialized queue, coded JSON errors, exit,
// timeout poisoning / never-replay).
// Determinism: every buffer is a fixed pattern; the only I/O is a temp
// directory under runs/ (removed on exit) plus one in-process loopback socket
// for the serve() smoke test (the same discipline as
// tests/protocol-conformance.cjs).
// Origin: original — BarbarismJB M5.
// Run: node tests/shell-sim.cjs   (exit 0 = all checks passed)
'use strict';
const assert = require('node:assert');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {Shell, tokenize, hexdump, COMMANDS} = require('../engine/lib/shell.cjs');
const {serve, Front} = require('../engine/lib/shell-server.cjs');

let passed = 0;
const failures = [];
function check(name, condition, detail = '') {
  if (condition) {passed++; process.stdout.write('  ok    ' + name + '\n');}
  else {failures.push(name + (detail ? ' — ' + detail : ''));
    process.stdout.write('  FAIL  ' + name + (detail ? ' — ' + detail : '') + '\n');}
}
async function expectError(name, code, promise) {
  try {await promise;} catch (error) {
    check(name, error.code === code, 'code ' + error.code + ' (want ' + code + '): ' + error.message);
    return error;
  }
  check(name, false, 'expected a rejection with ' + code + ', command succeeded');
  return null;
}

// ---- fakes --------------------------------------------------------------------

// Civshim-shaped bridge over a paged Map memory (no sockets).
class FakeBridge {
  constructor() {this.pages = new Map(); this.calls = []; this.allocs = []; this.nextAlloc = 0x5000000000;}
  page(address) {
    const index = Math.floor(address / 0x1000);
    if (!this.pages.has(index)) this.pages.set(index, Buffer.alloc(0x1000, 0));
    return this.pages.get(index);
  }
  async read(address, length) {
    this.calls.push(['read', address, length]);
    assert(Number.isInteger(length) && length > 0, 'fake bridge: bad read span');
    const out = Buffer.alloc(length);
    for (let at = 0; at < length; at++) out[at] = this.page(address + at)[(address + at) % 0x1000];
    return out;
  }
  async write(address, bytes) {
    this.calls.push(['write', address, bytes.length]);
    for (let at = 0; at < bytes.length; at++) this.page(address + at)[(address + at) % 0x1000] = bytes[at];
  }
  async query(address) {
    this.calls.push(['query', address]);
    const base = Math.floor(address / 0x1000) * 0x1000;
    return {address: BigInt(base), size: 0x1000n, type: 5, permissions: 3,
      attributes: 0, ipcReferences: 0, deviceReferences: 0};
  }
  async alloc(size) {this.calls.push(['alloc', size]); this.allocs.push(size);
    const address = this.nextAlloc; this.nextAlloc += 0x1000; return address;}
  async free(address) {this.calls.push(['free', address]);}
}

// memory.sock-shaped endpoint: scripted per-command replies + a files session.
class FakeFiles {
  constructor() {this.entries = new Map(); this.calls = [];}
  async list(dirPath) {this.calls.push(['list', dirPath]);
    return Array.from(this.entries, ([name, entry]) =>
      ({name, type: entry.type, size: entry.bytes.length}));}
  async stat(filePath) {this.calls.push(['stat', filePath]);
    const entry = this.entries.get(filePath);
    if (!entry) throw Error('not found: ' + filePath);
    return {type: entry.type, size: entry.bytes.length};}
  async size(filePath) {this.calls.push(['size', filePath]);
    return this.entries.get(filePath)?.bytes.length ?? -1;}
  async read(filePath, offset, length) {this.calls.push(['read', filePath, offset, length]);
    const entry = this.entries.get(filePath);
    if (!entry) throw Error('not found: ' + filePath);
    return entry.bytes.subarray(offset, offset + length);}
  async write(filePath, offset, bytes) {this.calls.push(['write', filePath, offset, bytes.length]);
    const entry = this.entries.get(filePath) || {type: 1, bytes: Buffer.alloc(0)};
    const grown = Buffer.alloc(Math.max(entry.bytes.length, offset + bytes.length));
    entry.bytes.copy(grown); bytes.copy(grown, offset);
    entry.bytes = grown; this.entries.set(filePath, entry);}
  async remove(target) {this.calls.push(['remove', target]); this.entries.delete(target);}
  async mkdir(target) {this.calls.push(['mkdir', target]); this.entries.set(target, {type: 2, bytes: Buffer.alloc(0)});}
  async df() {this.calls.push(['df']); return {free: 1000, total: 4096};}
}

class FakeEndpoint {
  constructor({files = true} = {}) {
    this.requests = [];
    this.handlers = new Map();
    if (files) this.files = new FakeFiles();
  }
  on(command, handler) {this.handlers.set(command, handler); return this;}
  async request(command) {
    this.requests.push(command);
    const handler = this.handlers.get(command.command);
    if (!handler) throw Error('fake endpoint: unscripted command ' + command.command);
    return handler(command);
  }
}

// process/client.cjs-shaped RO client.
class FakeRo {
  constructor() {
    this.pid = 0x2a; this.handle = 0x77;
    this.calls = [];
    this.patchReplies = [];
    this.processesRows = null;
  }
  async processHandle(pid) {this.calls.push(['processHandle', String(pid)]); return 0xffff8001;}
  async processes() {this.calls.push(['processes']);
    return this.processesRows ?? [{pid: 0x2a, programId: '0x0400000000000037', name: 'ro'},
      {pid: 0x41, programId: '0x0100000000001000', name: 'fs'}];}
  async bulkRead(handle, pid, address, length) {
    this.calls.push(['bulkRead', handle, String(pid), String(address), String(length)]);
    return {result: 0, bytes: pattern(String(address), Number(length))};
  }
  async read(handle, pid, address, length) {
    this.calls.push(['read11', handle, String(pid), String(address), String(length)]);
    return {result: 0, hex: pattern(String(address), Number(length)).toString('hex')};
  }
  async map(handle, pid, source, destination) {
    this.calls.push(['map', handle, String(pid), String(source), String(destination)]);
    return this.mapReply || {result: 0, mapResult: 0, permissionResult: 0, rollbackResult: 0};
  }
  async patch(handle, pid, address, expected, replacement) {
    this.calls.push(['patch', handle, String(pid), String(address),
      expected.toString('hex'), replacement.toString('hex')]);
    const reply = this.patchReplies.length > 1 ? this.patchReplies.shift() :
      this.patchReplies[0] || {result: 0, expectedMatched: true, readbackMatched: true};
    this.lastPatch = {expected: expected.toString('hex'), replacement: replacement.toString('hex')};
    return reply;
  }
}

// Deterministic byte pattern: position-dependent, so chunk stitching errors show.
function pattern(seed, length) {
  const bytes = Buffer.alloc(length);
  let state = 0n;
  for (const character of seed) state = (state * 131n + BigInt(character.charCodeAt(0))) & 0xffffn;
  for (let at = 0; at < length; at++) {
    state = (state * 251n + 11n) & 0xffffffffn;
    bytes[at] = Number((state >> 13n) & 0xffn);
  }
  return bytes;
}

function endpointWithBis(temp, chunk = 0x1000) {
  const endpoint = new FakeEndpoint();
  endpoint.on('info', () => ({ready: true, session: 'civ-test', plan: {target: 0}}));
  endpoint.on('root-info', () => ({clones: [0x99], initialized: true,
    storages: [{id: 30, handle: 0xa1}], filesystems: []}));
  endpoint.on('root-probe-bis', request => ({result: 0, opened: true,
    id: request.id, size: String(0x5000)}));
  endpoint.on('root-read-bis', async request => {
    const bytes = pattern('bis' + request.id, request.length);
    const outputFile = path.join(temp, 'bis-' + request.id + '-' + request.offset + '.bin');
    await fs.writeFile(outputFile, bytes, {mode: 0o600});
    return {id: request.id, offset: request.offset, length: request.length, outputFile,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex')};
  });
  return endpoint;
}

async function main() {
  const temp = await fs.mkdtemp(path.join(__dirname, '..', 'runs', 'shell-sim-'));
  const consoleLog = {debug() {}, info() {}, warn() {}, error() {}};
  try {
    process.stdout.write('shell simulation (offline, injected fakes)\n');

    // -- dispatch: every command is reachable and reports its subsystem -----
    const subsystems = new Set(COMMANDS.map(entry => entry.subsystem));
    check('dispatch table subsystems', JSON.stringify([...subsystems]) ===
      JSON.stringify(['meta', 'bridge', 'fs', 'ro']), 'got ' + [...subsystems]);
    check('dispatch table size', COMMANDS.length === 27, 'got ' + COMMANDS.length);
    for (const duplicates of [['help', 'exit']]) {
      const shell = new Shell(new FakeBridge(), endpointWithBis(temp), new FakeRo(), consoleLog);
      for (const name of duplicates) {
        const result = await shell.execute(name);
        check('dispatch ' + name, result.ok, JSON.stringify(result));
      }
    }

    // -- tokenizer ------------------------------------------------------------
    assert.deepEqual(tokenize('  read   0x1000  16 '), ['read', '0x1000', '16']);
    assert.deepEqual(tokenize("put 'my file.bin' /target"), ['put', 'my file.bin', '/target']);
    check('tokenizer quoting', true);
    await expectError('tokenizer unterminated quote', 'E_ARGS', Promise.resolve().then(() => tokenize('cat "oops')));

    // -- game memory via the bridge -------------------------------------------
    const bridge = new FakeBridge();
    const shell = new Shell(bridge, endpointWithBis(temp), new FakeRo(), consoleLog);
    await shell.execute('write64 0x7100000000 0x1122334455667788');
    const read64 = await shell.execute('read64 0x7100000000');
    check('write64/read64 round trip', read64.text === '0x1122334455667788', read64.text);
    check('write64 landed big-endian-safe', bridge.page(0x7100000000).readBigUInt64LE(0) === 0x1122334455667788n);
    const write = await shell.execute('write 0x7100000010 deadbeefcafebabe');
    const read = await shell.execute('read 0x7100000010 8');
    check('write/read byte round trip', read.dataHex === 'deadbeefcafebabe', read.dataHex);
    check('hex dump format', read.text ===
      '007100000010  de ad be ef ca fe ba be    |........|',
      JSON.stringify(read.text));
    const query = await shell.execute('query 0x7100000000');
    check('query reports mapping', query.text.includes('type    5') &&
      query.text.includes('perm    3'), query.text);
    const malloc = await shell.execute('malloc 0x2000');
    check('malloc returns address', typeof malloc.address === 'number' && malloc.address > 0x1000);
    const listing = await shell.execute('malloc');
    check('malloc listing tracks allocation', listing.text.includes('8192'), listing.text);
    await shell.execute('free ' + malloc.address);
    const listingAfter = await shell.execute('malloc');
    check('free drops allocation', listingAfter.text === 'no live shell allocations', listingAfter.text);

    // -- argument validation (coded E_ARGS) -----------------------------------
    await expectError('unknown command', 'E_ARGS', shell.execute('frobnicate'));
    await expectError('read64 bad address', 'E_ARGS', shell.execute('read64 nope'));
    await expectError('read64 below guest floor', 'E_ARGS', shell.execute('read64 0x10'));
    await expectError('read64 unaligned', 'E_ARGS', shell.execute('read64 0x7100000004'));
    await expectError('read64 wrong arity', 'E_ARGS', shell.execute('read64 0x7100000000 extra'));
    await expectError('write64 bad value', 'E_ARGS', shell.execute('write64 0x7100000000 zz'));
    await expectError('read over cap', 'E_ARGS', shell.execute('read 0x7100000000 0x20000'));
    await expectError('read zero length', 'E_ARGS', shell.execute('read 0x7100000000 0'));
    await expectError('write odd hex', 'E_ARGS', shell.execute('write 0x7100000010 abc'));
    await expectError('write empty hex', 'E_ARGS', shell.execute('write 0x7100000010'));
    await expectError('proc-patch wrong size', 'E_ARGS',
      shell.execute('proc-patch 0x2a 0x7100000000 aabb'));
    await expectError('proc-patch unaligned', 'E_ARGS',
      shell.execute('proc-patch 0x2a 0x7100000002 ' + 'aa'.repeat(16)));
    await expectError('exec-map unaligned source', 'E_ARGS',
      shell.execute('exec-map 0x2a 0x7100000001 0x90000000'));
    await expectError('bis id out of range', 'E_ARGS', shell.execute('bis-ls 19'));
    await expectError('relative console path', 'E_ARGS', shell.execute('cat saves/Single'));
    await expectError('bis: path rejected in v1', 'E_ARGS', shell.execute('cat bis:/30'));

    // -- disconnected subsystems (coded E_CONFIG naming the stage) ------------
    const offline = new Shell(null, null, null, consoleLog);
    const offlineBridge = new Shell(new FakeBridge(), null, null, consoleLog);
    const noFiles = new Shell(new FakeBridge(), new FakeEndpoint({files: false}), null, consoleLog);
    for (const [name, target, command] of [
      ['bridge', offline, 'read64 0x7100000000'],
      ['fs endpoint', offlineBridge, 'bis-ls'],
      ['fs endpoint (df)', offlineBridge, 'df'],
      ['ro client', offlineBridge, 'ps'],
      ['ro client (proc-read)', offlineBridge, 'proc-read 1 0x1000 16'],
      ['ro client (proc-patch)', offlineBridge, 'proc-patch 1 0x1000 ' + '00'.repeat(16)],
      ['ro client (exec-map)', offlineBridge, 'exec-map 1 0x1000 0x90000000'],
      ['save files session', noFiles, 'ls /'],
      ['save files session (cat)', noFiles, 'cat /main'],
      ['save files session (save-get)', noFiles, 'save-get /main /dev/null-x'],
      ['save files session (rm)', noFiles, 'rm /main'],
      ['save files session (mkdir)', noFiles, 'mkdir /d']]) {
      const error = await expectError('E_CONFIG without ' + name, 'E_CONFIG', target.execute(command));
      if (error) check('E_CONFIG message names the gap (' + name + ')',
        /M1|acquire|launch|mounted-save/.test(error.message), error.message);
    }

    // -- save session: ls/stat/cat + put/get chunking --------------------------
    const endpoint = endpointWithBis(temp);
    const session = new Shell(new FakeBridge(), endpoint, new FakeRo(), consoleLog);
    const payload = pattern('savefile', 0x18000); // 1.5 chunks
    await endpoint.files.write('save:/main', 0, payload);
    await endpoint.files.mkdir('save:/saves');
    const ls = await session.execute('ls /');
    check('ls lists entries with types', ls.text.includes('main') &&
      ls.text.includes('file') && ls.text.includes('dir'), ls.text);
    const stat = await session.execute('stat /main');
    check('stat size routes to save', stat.text.includes('size 98304') &&
      stat.text.includes('save mount'), stat.text);
    const cat = await session.execute('cat /main');
    check('cat under cap dumps bytes', cat.length === 0x18000 && cat.dataHex === payload.toString('hex'));
    const getLocal = path.join(temp, 'got.bin');
    const readsBefore = endpoint.files.calls.length;
    await session.execute('get /main ' + getLocal);
    check('get wrote exact bytes', (await fs.readFile(getLocal)).equals(payload));
    const readCalls = endpoint.files.calls.slice(readsBefore).filter(call => call[0] === 'read');
    check('get chunked at 0x10000', readCalls.length === 2 &&
      readCalls[0][3] === 0x10000 && readCalls[1][3] === 0x8000,
      JSON.stringify(readCalls));
    const saveLs = await session.execute('save-ls /');
    check('save-ls equals unprefixed routing', saveLs.entries.length === ls.entries.length);
    const putLocal = path.join(temp, 'put-source.bin');
    await fs.writeFile(putLocal, pattern('upload', 0x18001));
    const writesBefore = endpoint.files.calls.length;
    const put = await session.execute('put ' + putLocal + ' /uploaded.bin');
    const writeCalls = endpoint.files.calls.slice(writesBefore).filter(call => call[0] === 'write');
    check('put chunked at 0x10000', writeCalls.length === 2 &&
      writeCalls[0][3] === 0x10000 && writeCalls[1][3] === 0x8001, JSON.stringify(writeCalls));
    check('put content matches', endpoint.files.entries.get('save:/uploaded.bin').bytes
      .equals(pattern('upload', 0x18001)));
    check('put reports length', put.length === 0x18001);
    const existing = path.join(temp, 'exists.bin');
    await fs.writeFile(existing, Buffer.alloc(4));
    await expectError('get refuses to clobber', 'E_ARGS',
      session.execute('get /main ' + existing));
    await endpoint.files.write('save:/big', 0, Buffer.alloc(0x40001));
    const catError = await expectError('cat over cap suggests get', 'E_ARGS',
      session.execute('cat /big'));
    check('cat cap error names get', catError && catError.message.includes('get <path> <local>'),
      catError && catError.message);
    const df = await session.execute('df');
    check('df shows save + BIS rows', df.text.includes('save:') &&
      df.text.includes('bis:30'), df.text);

    // -- bis-ls / bis-get ------------------------------------------------------
    const bisLs = await session.execute('bis-ls');
    check('bis-ls lists USER/SYSTEM with sizes', bisLs.text.includes('USER') &&
      bisLs.text.includes('SYSTEM') && bisLs.text.includes('20480'), bisLs.text);
    const bisLocal = path.join(temp, 'bis.img');
    await session.execute('bis-get 30 0 0x5000 ' + bisLocal);
    check('bis-get wrote full range', (await fs.readFile(bisLocal)).equals(
      Buffer.concat([pattern('bis30', 0x4000), pattern('bis30', 0x1000)])));
    const bisReads = endpoint.requests.filter(request => request.command === 'root-read-bis');
    check('bis-get chunked at 0x4000', bisReads.length === 2 &&
      bisReads[0].length === 0x4000 && bisReads[1].length === 0x1000, JSON.stringify(bisReads));
    await expectError('bis-get over partition size', 'E_ARGS',
      session.execute('bis-get 30 0 0x6000 ' + path.join(temp, 'nope.bin')));
    // sha256 mismatch must be E_VERIFY: scripted chunk with a wrong hash.
    const fakeHashEndpoint = endpointWithBis(temp);
    fakeHashEndpoint.on('root-probe-bis', () => ({result: 0, size: String(0x4000)}));
    fakeHashEndpoint.on('root-read-bis', async request => {
      const bytes = pattern('bis' + request.id, request.length);
      const outputFile = path.join(temp, 'mismatch-' + request.offset + '.bin');
      await fs.writeFile(outputFile, bytes, {mode: 0o600});
      return {id: request.id, offset: request.offset, length: request.length, outputFile,
        sha256: '00'.repeat(32)}; // wrong hash on purpose
    });
    const hashSession = new Shell(new FakeBridge(), fakeHashEndpoint, new FakeRo(), consoleLog);
    await expectError('bis-get hash mismatch is E_VERIFY', 'E_VERIFY',
      hashSession.execute('bis-get 31 0 0x4000 ' + path.join(temp, 'bad.img')));

    // -- RO: ps / proc-read / proc-patch / exec-map -----------------------------
    const ro = new FakeRo();
    const roShell = new Shell(new FakeBridge(), endpointWithBis(temp), ro, consoleLog);
    const ps = await roShell.execute('ps');
    check('ps lists enumerated rows', ps.text.includes('42') &&
      ps.text.includes('ro') && ps.text.includes('fs'), ps.text);
    const procRead = await roShell.execute('proc-read 0x2a 0x4800000 0x100');
    check('proc-read bulk path (0x524F0016)', ro.calls.some(call => call[0] === 'bulkRead') &&
      procRead.dataHex === pattern('75497472', 0x100).toString('hex'));
    check('proc-read dump included', procRead.text.split('\n').length === 0x100 / 16);
    const fallbackRo = new FakeRo();
    fallbackRo.bulkRead = undefined; // prototype methods survive `delete`
    const fallbackShell = new Shell(new FakeBridge(), endpointWithBis(temp), fallbackRo, consoleLog);
    const smallRead = await fallbackShell.execute('proc-read 0x2a 0x1ff0 0x20'); // crosses a page
    const fallbackCalls = fallbackRo.calls.filter(call => call[0] === 'read11');
    check('proc-read fallback respects the 128B/page bound', fallbackCalls.length === 2 &&
      fallbackCalls[0][4] === '16' && fallbackCalls[1][4] === '16' &&
      smallRead.dataHex === Buffer.concat([pattern('8176', 16), pattern('8192', 16)]).toString('hex'),
      JSON.stringify(fallbackCalls));
    await expectError('proc-read fallback cap', 'E_ARGS',
      fallbackShell.execute('proc-read 0x2a 0x1000 0x2000'));
    const patch = await roShell.execute('proc-patch 0x2a 0x4800000 ' + 'aabbccdd'.repeat(4));
    check('proc-patch success message', patch.text.includes('patched') &&
      patch.text.includes('aabbccdd'), patch.text);
    check('proc-patch reads current bytes as expected (CAS)',
      ro.lastPatch.expected === pattern('75497472', 16).toString('hex'), ro.lastPatch.expected);
    ro.patchReplies = [{result: 0, expectedMatched: false, readbackMatched: false}];
    await expectError('proc-patch expected mismatch is E_VERIFY', 'E_VERIFY',
      roShell.execute('proc-patch 0x2a 0x4800000 ' + '11'.repeat(16)));
    const mapped = await roShell.execute('exec-map 0x2a 0x7000000000 0x90000000');
    check('exec-map reports RX grant', mapped.text.includes('is now RX'), mapped.text);
    ro.mapReply = {result: 0, mapResult: 0, permissionResult: 0xf201, rollbackResult: 0};
    const failed = await expectError('exec-map permission failure is E_VERIFY', 'E_VERIFY',
      roShell.execute('exec-map 0x2a 0x7000000000 0x91000000'));
    check('exec-map failure names the rollback', failed && failed.message.includes('rolled back'));
    ro.mapReply = null;

    // -- mount-info ----------------------------------------------------------------
    const info = await roShell.execute('mount-info');
    check('mount-info summarizes all three', info.text.includes('bridge (civshim') &&
      info.text.includes('fs endpoint') && info.text.includes('ro payload') &&
      info.text.includes('save session'), info.text);
    const partial = await new Shell(new FakeBridge(), null, null, consoleLog).execute('mount-info');
    check('mount-info without fs/ro still works', partial.text.includes('NOT CONNECTED'));
    check('help lists every command', (await roShell.execute('help')).text.split('\n')
      .filter(line => /^  \S/.test(line)).length === COMMANDS.length, 'help entries');
    const exit = await roShell.execute('exit');
    check('exit sets the exit flag', exit.exit === true && exit.ok);

    // -- server front (socket-free core) ---------------------------------------------
    const front = new Front(new Shell(new FakeBridge(), endpointWithBis(temp), new FakeRo(), consoleLog),
      {timeoutMs: 5000});
    const reply = await front.command('read64 0x7100000000');
    check('front ok reply shape', reply.ok === true && typeof reply.text === 'string');
    const bad = await front.command('read64 zzz');
    check('front coded error reply', bad.ok === false && bad.code === 'E_ARGS', JSON.stringify(bad));
    const exitReply = await front.command('exit');
    check('front passes exit through', exitReply.ok && exitReply.exit === true);
    // serialization: the queue runs one command at a time in submission order.
    const order = [];
    const slowShell = new Shell(new FakeBridge(), endpointWithBis(temp), new FakeRo(), consoleLog);
    slowShell.dispatch.query.run = async () => {
      order.push('query:start');
      await new Promise(resolve => setTimeout(resolve, 20));
      order.push('query:end');
      return {text: 'ok'};
    };
    const serialFront = new Front(slowShell, {timeoutMs: 5000});
    await Promise.all([serialFront.command('query 0x1000'), serialFront.command('help')]);
    check('front serializes commands', order[0] === 'query:start' && order[1] === 'query:end');
    // timeout poisoning / never-replay.
    const hanging = new Shell(new FakeBridge(), endpointWithBis(temp), new FakeRo(), consoleLog);
    hanging.dispatch.query.run = () => new Promise(() => {}); // never settles
    const poisonedFront = new Front(hanging, {timeoutMs: 40});
    const timedOut = await poisonedFront.command('query 0x1000');
    check('front timeout is coded E_TIMEOUT', timedOut.ok === false &&
      timedOut.code === 'E_TIMEOUT' && timedOut.error.includes('replayed'), JSON.stringify(timedOut));
    const after = await poisonedFront.command('help');
    check('front poisoned after timeout', after.code === 'E_TIMEOUT' &&
      after.error.includes('poisoned'), JSON.stringify(after));
    // transport failures poison too.
    const dropping = new FakeBridge();
    dropping.read = async () => {throw Object.assign(Error('socket hangup'), {code: 'E_TRANSPORT'});};
    const transportFront = new Front(new Shell(dropping, null, null, consoleLog), {timeoutMs: 1000});
    const dropped = await transportFront.command('read 0x7100000000 8');
    check('transport failure is coded', dropped.code === 'E_TRANSPORT');
    const afterDrop = await transportFront.command('help');
    check('front poisoned after transport failure', afterDrop.code === 'E_TIMEOUT');

    // -- serve() smoke test over one in-process loopback socket ----------------------
    const listener = await serve(new Shell(new FakeBridge(), endpointWithBis(temp), new FakeRo(), consoleLog),
      {port: 0});
    const net = require('node:net');
    const lines = [];
    await new Promise((resolve, reject) => {
      const socket = net.connect(listener.port, '127.0.0.1');
      socket.setEncoding('utf8');
      let buffer = '';
      socket.on('error', reject);
      socket.on('connect', () => socket.write(JSON.stringify({line: 'read64 0x7100000000'}) + '\n' +
        JSON.stringify({line: 'nope'}) + '\n' +
        JSON.stringify({line: 'exit'}) + '\n'));
      socket.on('data', chunk => {
        buffer += chunk;
        let at;
        while ((at = buffer.indexOf('\n')) >= 0) {lines.push(buffer.slice(0, at)); buffer = buffer.slice(at + 1);}
      });
      socket.on('close', resolve);
    });
    const [first, second, third] = lines.map(JSON.parse);
    check('serve(): ok reply over TCP', first.ok === true && first.text === '0x0');
    check('serve(): coded error over TCP', second.ok === false && second.code === 'E_ARGS');
    check('serve(): exit closes the client', third.exit === true && lines.length === 3);
    await listener.close();

    // -- python client syntax ---------------------------------------------------------
    const {execFile} = require('node:child_process');
    const pyCheck = await new Promise(resolve =>
      execFile('python3', ['-m', 'py_compile', path.join(__dirname, '..', 'tools', 'shell_client.py')],
        error => resolve(!error)));
    check('shell_client.py compiles', pyCheck);
    const pyHelp = await new Promise(resolve =>
      execFile('python3', [path.join(__dirname, '..', 'tools', 'shell_client.py'), '--help'],
        error => resolve(!error)));
    check('shell_client.py --help exits 0', pyHelp);
  } finally {
    await fs.rm(temp, {recursive: true, force: true});
  }

  process.stdout.write('\n────────────────────────────────────────────\n');
  process.stdout.write('  shell simulation checks passed: ' + passed + '\n');
  if (failures.length) {
    process.stdout.write('  FAILED: ' + failures.length + '\n');
    for (const failure of failures) process.stdout.write('    - ' + failure + '\n');
    return 1;
  }
  process.stdout.write('  ALL GREEN\n');
  return 0;
}

main().then(code => {process.exitCode = code;}, error => {
  console.error(error && error.stack || error);
  process.exitCode = 1;
});
