// engine/lib/shell.cjs — the BarbarismJB shell: a host-driven command layer
// over the three post-exploitation primitives (M5, v1).
//
// Purpose: give the operator one interpreter for everything the chain holds
// after each stage — game-process memory (civshim bridge), the fs-process
// memory endpoint with its PID→1 FullPermission fsp-srv root (BIS storage,
// mount/session state, and — once wired — the game-save file session), and
// the RO payload process server (query/read/patch/map-exec of arbitrary
// processes). No shell exists anywhere on Switch 2 today; this is the first.
// It executes on the HOST: every command fans out to one of the injected
// subsystem clients below, so nothing new runs on the console.
//
// Subsystem routing (who executes what, and where the permission lives):
//   bridge     — a Civshim instance (engine/lib/bridge.cjs). CALL / READ /
//                WRITE / QUERY / ALLOC / FREE inside the Civ 7 game process.
//                Permission: the game process itself. Connected from M1
//                (payloads/civshim.js + node run.cjs).
//   fsEndpoint — the retained memory endpoint client (the object returned by
//                engine/switch2/tools/fs-memory.cjs connect(), fronting the
//                run-folder memory.sock command set of
//                engine/switch2/memory/fs-memory-control.cjs). Used for:
//                'info' / 'retained-info' (readiness), 'root-info' (the
//                dedicated PID→1 fsp-srv root: clones/storages/filesystems),
//                'root-probe-bis' + 'root-read-bis' (raw BIS storage reads).
//                Permission: fs sysmodule / PID 1 FullPermission. Connected
//                after --stage acquire (+ pid).
//   fsEndpoint.files — OPTIONAL file session for the game's own save: mount
//                (save-ls/save-get/save-put and unprefixed file paths).
//                Surface: {list(path), stat(path), size(path), read(path,
//                offset, length), write(path, offset, bytes), remove(path),
//                mkdir(path), df()}. run.cjs wires it through the app session
//                once the Civ 7 port of engine/switch2/app/mounted-save.cjs
//                lands (README.md "Pending Civ 7 ports"); until then every
//                file command fails with E_CONFIG naming that port, never a
//                crash.
//   roClient   — the RO process client (engine/switch2/process/client.cjs
//                Client shape) driving the ro:dmnt process server commands
//                0x524F0010–0x524F0016. Used for: ps (via the optional
//                processes() enumeration), proc-read (0x524F0016 bulkRead,
//                0x524F0011 chunk fallback), proc-patch (0x524F0014 with the
//                current 16 bytes read first as the primitive's expected
//                value), exec-map (0x524F0012 one-page RX grant). Permission:
//                any process the wiring can hand a KProcess handle for via
//                processHandle(pid). Connected after --stage launch.
//
// Errors: every failure carries a stable code from engine/shared/errors.cjs —
// E_ARGS (validation), E_CONFIG (subsystem not connected; the message names
// the stage/port that must run first), E_PROTOCOL / E_TIMEOUT / E_TRANSPORT
// (underlying client failures), E_VERIFY (readback/hash/expected mismatch),
// E_INTERNAL (bug). Uncoded adapter errors are wrapped, never crashed on.
//
// Origin: original — BarbarismJB M5. Docs: docs/SHELL.md (command reference,
// server/client wiring, security notes, v2 design).
'use strict';
const fs = require('node:fs/promises');
const crypto = require('node:crypto');
const {fail, withCode} = require('../shared/errors.cjs');

// Single-op caps, all taken from the underlying primitives:
const BRIDGE_STREAM = 0x80000;  // one civshim READ/WRITE (bridge.cjs MAX_STREAM)
const READ_CAP = 0x10000;       // one `read` hex dump (output stays printable)
const WRITE_CAP = 0x10000;      // one `write` payload (fs-side write cap)
const FILE_CHUNK = 0x10000;     // save-file get/put chunk (donor staging size)
const CAT_CAP = 0x40000;        // one `cat` (4 chunks)
const BIS_CHUNK = 0x4000;       // one root-read-bis (fs-root-control cap)
const BIS_IDS = [30, 31];       // USER / SYSTEM (fs-root-control probe range)
const BULK_READ_CAP = 0x400000; // RO 0x524F0016 receive-window cap
const CHUNK_READ_CAP = 0x1000;  // cap for the 0x524F0011 per-128B fallback
const MIN_ADDRESS = 0x1000n;    // below this no mapping ever exists
const MAX_ADDRESS = 2n ** 47n;  // Switch 2 userland never reaches here
const MAX_U64 = 2n ** 64n - 1n;

// ---- argument parsing --------------------------------------------------------

// Split a command line on whitespace with '...' / "..." quoting support.
function tokenize(line) {
  if (typeof line !== 'string') throw fail('E_ARGS', 'Command must be a string');
  const tokens = [];
  let at = 0;
  while (at < line.length) {
    while (at < line.length && /\s/.test(line[at])) at++;
    if (at >= line.length) break;
    const quote = line[at] === '"' || line[at] === "'" ? line[at++] : null;
    let token = '';
    if (quote) {
      while (at < line.length && line[at] !== quote) token += line[at++];
      if (at >= line.length) throw fail('E_ARGS', 'Unterminated quote in command line');
      at++;
    } else while (at < line.length && !/\s/.test(line[at])) token += line[at++];
    tokens.push(token);
  }
  return tokens;
}

// Exact non-negative integer, decimal or 0x-hex, as BigInt.
function integer(text, what) {
  if (typeof text !== 'string' || !/^(?:0[xX][0-9a-fA-F]+|[0-9]+)$/.test(text))
    throw fail('E_ARGS', 'Invalid ' + what + ' "' + text + '" — use decimal or 0x-hex');
  const value = BigInt(text);
  if (value > MAX_U64)
    throw fail('E_ARGS', 'Invalid ' + what + ' — above 2^64');
  return value;
}

function guestAddress(text, what) {
  const value = integer(text, what);
  if (value < MIN_ADDRESS || value >= MAX_ADDRESS)
    throw fail('E_ARGS', 'Invalid ' + what + ' 0x' + value.toString(16) +
      ' — outside plausible guest memory (0x1000..2^47)');
  return value;
}

function hexBytes(text, what, {min = 1, max = WRITE_CAP} = {}) {
  if (typeof text !== 'string' || !/^[0-9a-fA-F]+$/.test(text) || text.length % 2)
    throw fail('E_ARGS', 'Invalid ' + what + ' — expected an even-length hex string');
  const bytes = Buffer.from(text, 'hex');
  if (bytes.length < min || bytes.length > max)
    throw fail('E_ARGS', 'Invalid ' + what + ' length ' + bytes.length +
      ' — allowed ' + min + '..' + max + ' bytes');
  return bytes;
}

function positiveLength(text, what, cap) {
  const value = integer(text, what);
  if (value < 1n || value > BigInt(cap))
    throw fail('E_ARGS', 'Invalid ' + what + ' — allowed 1..' + cap);
  return value;
}

function consolePath(text, what) {
  if (typeof text !== 'string' || !text.length || text.includes('\0') || text.length > 0x300)
    throw fail('E_ARGS', 'Invalid ' + what + ' "' + text + '"');
  if (!text.startsWith('/')) throw fail('E_ARGS',
    'Invalid ' + what + ' "' + text + '" — console paths are absolute and start with /' +
    ' (prefix save:/ for the game mount; see help)');
  return text;
}

const hex = value => '0x' + BigInt(value).toString(16);

// Classic 16-per-line dump: address, 8+8 hex bytes, |ascii|.
function hexdump(address, bytes) {
  const lines = [];
  for (let at = 0; at < bytes.length; at += 16) {
    const chunk = bytes.subarray(at, at + 16);
    const pair = Array.from(chunk, byte => byte.toString(16).padStart(2, '0'));
    const left = pair.slice(0, 8).join(' ').padEnd(23);
    const right = pair.slice(8).join(' ').padStart(chunk.length > 8 ? 23 : 0);
    const ascii = Array.from(chunk, byte =>
      byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.').join('');
    lines.push((address + BigInt(at)).toString(16).padStart(12, '0') + '  ' +
      left + '  ' + right + '  |' + ascii + '|');
  }
  return lines.join('\n');
}

// ---- the shell ---------------------------------------------------------------

class Shell {
  // bridge: Civshim | null; fsEndpoint: memory endpoint client | null;
  // roClient: process client | null; log: createLog() instance | null.
  constructor(bridge = null, fsEndpoint = null, roClient = null, log = null) {
    this.bridge = bridge || null;
    this.fsEndpoint = fsEndpoint || null;
    this.roClient = roClient || null;
    this.log = log || {debug() {}, info() {}, warn() {}, error() {}};
    this.allocations = new Map(); // address(string) -> size, from malloc/free
    this.calls = 0;
    this.dispatch = Object.fromEntries(COMMANDS.map(entry => [entry.name, entry]));
  }

  requireBridge(command) {
    if (!this.bridge) throw fail('E_CONFIG', 'the civshim bridge is not connected' +
      ' — send payloads/civshim.js through the :9026 loader and connect first (M1);' +
      ' command: ' + command);
    return this.bridge;
  }

  requireFs(command) {
    if (!this.fsEndpoint) throw fail('E_CONFIG', 'the fs memory endpoint is not connected' +
      ' — run the acquire (and pid) stage first: node run.cjs --stage acquire <ip>;' +
      ' command: ' + command);
    return this.fsEndpoint;
  }

  requireRo(command) {
    if (!this.roClient) throw fail('E_CONFIG', 'the RO process server is not connected' +
      ' — run the launch stage first: node run.cjs --stage launch <ip>;' +
      ' command: ' + command);
    return this.roClient;
  }

  requireFiles(command) {
    const endpoint = this.requireFs(command);
    if (!endpoint.files) throw fail('E_CONFIG', 'the game save file session is not wired' +
      ' — it needs the pending Civ 7 port of engine/switch2/app/mounted-save.cjs' +
      ' (README.md "Pending Civ 7 ports"); raw BIS (bis-ls/bis-get) works today;' +
      ' command: ' + command);
    return endpoint.files;
  }

  // One serialized fs-endpoint request; endpoint errors keep their own shape
  // (plain Errors from the controller) and gain E_TRANSPORT here.
  async fsRequest(command, request) {
    const endpoint = this.requireFs(command);
    try {
      return await endpoint.request(request);
    } catch (error) {
      if (error && error.code) throw error;
      throw withCode(error, 'E_TRANSPORT');
    }
  }

  // Resolve the target pid string and a KProcess handle for it.
  async roTarget(command, pidText) {
    const ro = this.requireRo(command);
    const pid = integer(pidText, 'pid');
    let handle;
    try {
      handle = typeof ro.processHandle === 'function' ? await ro.processHandle(pid) : null;
    } catch (error) {throw withCode(error, 'E_TRANSPORT');}
    if (!handle || typeof handle !== 'number' && typeof handle !== 'bigint')
      throw fail('E_CONFIG', 'the roClient wiring does not resolve processHandle(' +
        pidText + ') — run.cjs must map pids to retained KProcess handles' +
        ' (see docs/SHELL.md "wiring contract")');
    return {ro, pid, handle: Number(handle)};
  }

  // Parse and run one command line. Resolves {ok:true, text, ...}; rejects
  // with a coded Error for anything else. `exit` resolves {ok:true, exit:true}.
  async execute(line) {
    const argv = tokenize(line);
    if (!argv.length) return {ok: true, text: ''};
    const [name, ...rest] = argv;
    const entry = this.dispatch[name];
    if (!entry) throw fail('E_ARGS', 'Unknown command: ' + name + ' (try help)');
    this.log.debug('shell: %s %s', name, rest.join(' '));
    const result = await entry.run.call(this, rest);
    this.calls++;
    return {ok: true, ...result};
  }

  help() {
    const bySubsystem = new Map();
    for (const entry of COMMANDS) {
      if (entry.hidden) continue;
      const group = bySubsystem.get(entry.subsystem) || [];
      group.push(entry);
      bySubsystem.set(entry.subsystem, group);
    }
    const out = ['BarbarismJB shell — commands by subsystem (stage that provides it):'];
    for (const [subsystem, entries] of bySubsystem) {
      const label = SUBSYSTEMS[subsystem];
      out.push('', label.stage + ' — ' + label.what + ':');
      for (const entry of entries)
        out.push('  ' + (entry.usage).padEnd(34) + entry.help);
    }
    out.push('', 'Addresses/lengths accept decimal or 0x-hex. Console paths are absolute;',
      'unprefixed paths and save:/ route to the game save mount, bis:<id> to BIS.');
    return out.join('\n');
  }
}

const SUBSYSTEMS = {
  bridge: {stage: 'M1 bridge (civshim, game process memory)', what: 'civshim :39381 ops'},
  fs: {stage: '--stage acquire (fs endpoint + PID 1 fsp-srv root)', what: 'memory.sock + BIS + save session'},
  ro: {stage: '--stage launch (RO payload process server)', what: 'ro:dmnt 0x524F00xx'},
  meta: {stage: 'always available', what: 'shell itself'},
};

const COMMANDS = [
  // -- always available --------------------------------------------------------
  {name: 'help', usage: 'help', subsystem: 'meta',
    help: 'this command reference',
    run() {return {text: this.help()};}},
  {name: 'exit', usage: 'exit', subsystem: 'meta',
    help: 'end this shell session (the host connection stays up)',
    run() {return {text: 'bye', exit: true};}},

  // -- bridge: game process memory ---------------------------------------------
  {name: 'query', usage: 'query <addr>', subsystem: 'bridge',
    help: 'svcQueryMemory at addr (mapping base/size/type/perm)',
    run(argv) {
      if (argv.length !== 1) throw fail('E_ARGS', 'usage: query <addr>');
      const address = guestAddress(argv[0], 'address');
      const bridge = this.requireBridge('query');
      return bridge.query(Number(address)).then(region => ({text:
        'base    ' + hex(region.address) + '\n' +
        'size    ' + hex(region.size) + '\n' +
        'type    ' + region.type + '\n' +
        'perm    ' + region.permissions}));
    }},
  {name: 'read64', usage: 'read64 <addr>', subsystem: 'bridge',
    help: 'read one little-endian u64',
    run(argv) {
      if (argv.length !== 1) throw fail('E_ARGS', 'usage: read64 <addr>');
      const address = guestAddress(argv[0], 'address');
      const bridge = this.requireBridge('read64');
      if ((address & 7n) !== 0n) throw fail('E_ARGS', 'read64 address must be 8-aligned');
      return bridge.read(Number(address), 8).then(bytes => ({text: hex(bytes.readBigUInt64LE()),
        dataHex: bytes.toString('hex')}));
    }},
  {name: 'write64', usage: 'write64 <addr> <val>', subsystem: 'bridge',
    help: 'write one little-endian u64',
    run(argv) {
      if (argv.length !== 2) throw fail('E_ARGS', 'usage: write64 <addr> <val>');
      const address = guestAddress(argv[0], 'address');
      const value = integer(argv[1], 'value');
      if ((address & 7n) !== 0n) throw fail('E_ARGS', 'write64 address must be 8-aligned');
      const bytes = Buffer.alloc(8);
      bytes.writeBigUInt64LE(value);
      const bridge = this.requireBridge('write64');
      return bridge.write(Number(address), bytes).then(() =>
        ({text: 'wrote ' + hex(value) + ' at ' + hex(address)}));
    }},
  {name: 'read', usage: 'read <addr> <len>', subsystem: 'bridge',
    help: 'read memory and hex-dump it (len <= 0x10000)',
    run(argv) {
      if (argv.length !== 2) throw fail('E_ARGS', 'usage: read <addr> <len>');
      const address = guestAddress(argv[0], 'address');
      const length = positiveLength(argv[1], 'length', READ_CAP);
      const bridge = this.requireBridge('read');
      return bridge.read(Number(address), Number(length)).then(bytes =>
        ({text: hexdump(address, bytes), dataHex: bytes.toString('hex'),
          address: address.toString(), length: bytes.length}));
    }},
  {name: 'write', usage: 'write <addr> <hex>', subsystem: 'bridge',
    help: 'write hex bytes (<= 0x10000 per command, civshim-chunked)',
    run(argv) {
      if (argv.length !== 2) throw fail('E_ARGS', 'usage: write <addr> <hex>');
      const address = guestAddress(argv[0], 'address');
      const bytes = hexBytes(argv[1], 'hex payload');
      const bridge = this.requireBridge('write');
      const send = [];
      for (let at = 0; at < bytes.length; at += BRIDGE_STREAM)
        send.push(bridge.write(Number(address) + at, bytes.subarray(at, at + BRIDGE_STREAM)));
      return Promise.all(send).then(() =>
        ({text: 'wrote ' + bytes.length + ' bytes at ' + hex(address)}));
    }},
  {name: 'malloc', usage: 'malloc <size> | malloc', subsystem: 'bridge',
    help: 'game calloc (no args: list live shell allocations)',
    run(argv) {
      const bridge = this.requireBridge('malloc');
      if (!argv.length) {
        if (!this.allocations.size) return {text: 'no live shell allocations'};
        const lines = Array.from(this.allocations, ([at, size]) =>
          at.padEnd(14) + size).sort();
        return {text: 'address       size\n' + lines.join('\n')};
      }
      if (argv.length !== 1) throw fail('E_ARGS', 'usage: malloc <size>');
      const size = positiveLength(argv[0], 'size', 0x40000000);
      return bridge.alloc(Number(size)).then(address => {
        if (!Number.isSafeInteger(address) || address < 0x1000)
          throw fail('E_PROTOCOL', 'calloc returned an implausible address');
        this.allocations.set(String(address), Number(size));
        return {text: hex(address), address, size: Number(size)};
      });
    }},
  {name: 'free', usage: 'free <addr>', subsystem: 'bridge',
    help: 'game free of a malloc address',
    run(argv) {
      if (argv.length !== 1) throw fail('E_ARGS', 'usage: free <addr>');
      const address = guestAddress(argv[0], 'address');
      const bridge = this.requireBridge('free');
      return bridge.free(Number(address)).then(() => {
        this.allocations.delete(String(Number(address)));
        return {text: 'freed ' + hex(address)};
      });
    }},

  // -- fs endpoint: save session / BIS / mounts --------------------------------
  {name: 'ls', usage: 'ls <path>', subsystem: 'fs',
    help: 'list a directory (routes: save mount by default, save:/ explicitly)',
    run(argv) {
      if (argv.length !== 1) throw fail('E_ARGS', 'usage: ls <path>');
      return listDirectory(this, normalizeConsolePath(argv[0], 'path'));
    }},
  {name: 'stat', usage: 'stat <path>', subsystem: 'fs',
    help: 'entry type and size (same routing as ls)',
    run(argv) {
      if (argv.length !== 1) throw fail('E_ARGS', 'usage: stat <path>');
      return statPath(this, normalizeConsolePath(argv[0], 'path'));
    }},
  {name: 'cat', usage: 'cat <path>', subsystem: 'fs',
    help: 'print a file (<= 0x40000, hex-dumped)',
    run(argv) {
      if (argv.length !== 1) throw fail('E_ARGS', 'usage: cat <path>');
      return readConsoleFile(this, normalizeConsolePath(argv[0], 'path'), CAT_CAP)
        .then(bytes => ({text: hexdump(0n, bytes), dataHex: bytes.toString('hex'),
          length: bytes.length}));
    }},
  {name: 'put', usage: 'put <local> <path>', subsystem: 'fs',
    help: 'upload a host file to the console (0x10000 chunks)',
    run(argv) {
      if (argv.length !== 2) throw fail('E_ARGS', 'usage: put <local> <path>');
      const target = normalizeConsolePath(argv[1], 'console path');
      return putLocalFile(this, argv[0], target);
    }},
  {name: 'get', usage: 'get <path> <local>', subsystem: 'fs',
    help: 'download a console file to the host (0x10000 chunks)',
    run(argv) {
      if (argv.length !== 2) throw fail('E_ARGS', 'usage: get <path> <local>');
      const source = normalizeConsolePath(argv[0], 'console path');
      return getConsoleFile(this, source, argv[1]);
    }},
  {name: 'rm', usage: 'rm <path>', subsystem: 'fs',
    help: 'delete a console file (same routing as ls)',
    run(argv) {
      if (argv.length !== 1) throw fail('E_ARGS', 'usage: rm <path>');
      const files = this.requireFiles('rm');
      const target = normalizeConsolePath(argv[0], 'path');
      return Promise.resolve(files.remove(target)).then(() =>
        ({text: 'removed ' + target}));
    }},
  {name: 'mkdir', usage: 'mkdir <path>', subsystem: 'fs',
    help: 'create a console directory (same routing as ls)',
    run(argv) {
      if (argv.length !== 1) throw fail('E_ARGS', 'usage: mkdir <path>');
      const files = this.requireFiles('mkdir');
      const target = normalizeConsolePath(argv[0], 'path');
      return Promise.resolve(files.mkdir(target)).then(() =>
        ({text: 'created ' + target}));
    }},
  {name: 'df', usage: 'df', subsystem: 'fs',
    help: 'free/total space of connected storages (save mount + BIS)',
    run() {
      return storageReport(this);
    }},
  {name: 'save-ls', usage: 'save-ls <path>', subsystem: 'fs',
    help: 'ls on the game save mount (root is the save root — never /saves)',
    run(argv) {
      if (argv.length !== 1) throw fail('E_ARGS', 'usage: save-ls <path>');
      return listDirectory(this, savePath(argv[0]));
    }},
  {name: 'save-get', usage: 'save-get <path> <local>', subsystem: 'fs',
    help: 'download from the game save mount (XSTRIG trigger is read-only)',
    run(argv) {
      if (argv.length !== 2) throw fail('E_ARGS', 'usage: save-get <path> <local>');
      return getConsoleFile(this, savePath(argv[0]), argv[1]);
    }},
  {name: 'save-put', usage: 'save-put <local> <path>', subsystem: 'fs',
    help: 'upload to the game save mount (root-level files only)',
    run(argv) {
      if (argv.length !== 2) throw fail('E_ARGS', 'usage: save-put <local> <path>');
      return putLocalFile(this, argv[0], savePath(argv[1]));
    }},
  {name: 'bis-ls', usage: 'bis-ls [id]', subsystem: 'fs',
    help: 'BIS storage partitions (default: 30 USER + 31 SYSTEM)',
    run(argv) {
      const ids = argv.length ? [bisId(argv[0])] : BIS_IDS;
      if (argv.length > 1) throw fail('E_ARGS', 'usage: bis-ls [id]');
      return bisListing(this, ids);
    }},
  {name: 'bis-get', usage: 'bis-get <id> <off> <len> <local>', subsystem: 'fs',
    help: 'raw BIS storage range to a host file (0x4000 chunks, id 30|31)',
    run(argv) {
      if (argv.length !== 4) throw fail('E_ARGS', 'usage: bis-get <id> <off> <len> <local>');
      const id = bisId(argv[0]);
      const offset = integer(argv[1], 'offset');
      const length = positiveLength(argv[2], 'length', 0x10000000);
      return bisGet(this, id, offset, length, argv[3]);
    }},
  {name: 'mount-info', usage: 'mount-info', subsystem: 'fs',
    help: 'which subsystems/sessions are connected and their permission level',
    run() {
      return mountInfo(this);
    }},

  // -- ro payload process server -------------------------------------------------
  {name: 'ps', usage: 'ps', subsystem: 'ro',
    help: 'process list (RO identity + pm info; falls back to session rows)',
    run() {
      return processList(this);
    }},
  {name: 'proc-read', usage: 'proc-read <pid> <addr> <len>', subsystem: 'ro',
    help: 'read another process (RO 0x524F0016, <= 4 MiB)',
    run(argv) {
      if (argv.length !== 3) throw fail('E_ARGS', 'usage: proc-read <pid> <addr> <len>');
      const address = guestAddress(argv[1], 'address');
      const length = positiveLength(argv[2], 'length', BULK_READ_CAP);
      const target = this.roTarget('proc-read', argv[0]);
      return target.then(({ro, pid, handle}) =>
        procRead(ro, handle, pid, address, length));
    }},
  {name: 'proc-patch', usage: 'proc-patch <pid> <addr> <hex16>', subsystem: 'ro',
    help: 'patch exactly 16 bytes (RO 0x524F0014; current bytes are read first' +
      ' and used as the primitive expected value)',
    run(argv) {
      if (argv.length !== 3) throw fail('E_ARGS', 'usage: proc-patch <pid> <addr> <hex16>');
      const address = guestAddress(argv[1], 'address');
      if ((address & 3n) !== 0n) throw fail('E_ARGS', 'proc-patch address must be 4-aligned');
      const replacement = hexBytes(argv[2], 'replacement', {min: 16, max: 16});
      const target = this.roTarget('proc-patch', argv[0]);
      return target.then(({ro, pid, handle}) => procPatch(ro, handle, pid, address, replacement));
    }},
  {name: 'exec-map', usage: 'exec-map <pid> <src> <dst>', subsystem: 'ro',
    help: 'grant RX to one RW page of a process at a free VA (RO 0x524F0012;' +
      ' the M7 loader primitive — source page must stay live afterwards)',
    run(argv) {
      if (argv.length !== 3) throw fail('E_ARGS', 'usage: exec-map <pid> <src> <dst>');
      const source = guestAddress(argv[1], 'source page');
      const destination = guestAddress(argv[2], 'destination page');
      for (const [value, what] of [[source, 'source'], [destination, 'destination']])
        if ((value & 0xfffn) !== 0n) throw fail('E_ARGS', what + ' must be 0x1000-aligned');
      const target = this.roTarget('exec-map', argv[0]);
      return target.then(({ro, pid, handle}) =>
        Promise.resolve(ro.map(handle, pid, source, destination)).then(reply => {
          if (reply.result) throw fail('E_PROTOCOL',
            'RO map failed: 0x' + Number(reply.result).toString(16));
          const text = 'map 0x' + Number(reply.mapResult).toString(16) +
            '  permission 0x' + Number(reply.permissionResult).toString(16) +
            '  rollback 0x' + Number(reply.rollbackResult).toString(16);
          if (reply.permissionResult) throw fail('E_VERIFY', text +
            ' — permission change failed; the source page was rolled back');
          return {text: text + '\n' + hex(destination) + ' is now RX in pid ' + pid,
            source: source.toString(), destination: destination.toString()};
        }));
    }},
];

// ---- path routing --------------------------------------------------------------

// Route a console path to (files-adapter, path). v1 routing:
//   save:/... or unprefixed -> the game save mount (fsEndpoint.files)
//   bis:<id>/...            -> rejected here; use bis-ls / bis-get (raw storage)
function normalizeConsolePath(text, what) {
  const raw = consolePath(text, what);
  if (raw.startsWith('save:')) return savePath(raw.slice(5));
  if (/^bis/i.test(raw)) throw fail('E_ARGS',
    'bis: paths are raw storage — use bis-ls / bis-get (no filesystem layer in v1)');
  return savePath(raw);
}

function savePath(text, what = 'path') {
  const raw = consolePath(text, what);
  const path = raw.startsWith('save:') ? raw.slice(5) : raw;
  if (!path.startsWith('/')) throw fail('E_ARGS', 'Invalid ' + what + ' "' + text +
    '" — console paths are absolute and start with /');
  return 'save:' + path;
}

function bisId(text) {
  const id = Number(integer(text, 'BIS id'));
  if (!BIS_IDS.includes(id)) throw fail('E_ARGS',
    'BIS id must be one of ' + BIS_IDS.join(', ') + ' (USER, SYSTEM) in v1');
  return id;
}

// ---- fs helpers -----------------------------------------------------------------

async function listDirectory(shell, path) {
  const files = shell.requireFiles('ls');
  let entries;
  try {entries = await files.list(path);}
  catch (error) {throw withCode(error, 'E_TRANSPORT');}
  if (!Array.isArray(entries)) throw fail('E_PROTOCOL', 'file session list() malformed');
  const rows = entries.map(entry => {
    if (!entry || typeof entry.name !== 'string') throw fail('E_PROTOCOL',
      'file session list() returned a malformed entry');
    const type = entry.type === 2 ? 'dir' : entry.type === 1 ? 'file' : '?' + entry.type;
    return (entry.name).padEnd(40) + type.padEnd(6) + (entry.size ?? '-');
  });
  return {text: (rows.length ? rows.join('\n') : '(empty)'), entries};
}

async function statPath(shell, path) {
  const files = shell.requireFiles('stat');
  let entry;
  try {entry = await files.stat(path);}
  catch (error) {throw withCode(error, 'E_TRANSPORT');}
  if (!entry || (entry.type !== 1 && entry.type !== 2))
    throw fail('E_PROTOCOL', 'file session stat() malformed');
  return {text: (entry.type === 2 ? 'dir ' : 'file') + '  ' + path +
    '  size ' + (entry.size ?? '-') + '\nrouted to: game save mount (save:)',
    entry};
}

async function fileSize(shell, command, path) {
  const files = shell.requireFiles(command);
  if (typeof files.size === 'function') {
    const size = await files.size(path);
    if (!Number.isSafeInteger(size) || size < 0) throw fail('E_PROTOCOL',
      'file session size() returned a malformed value');
    return size;
  }
  const entry = await files.stat(path);
  if (!Number.isSafeInteger(entry?.size) || entry.size < 0) throw fail('E_PROTOCOL',
    'file session stat() returned no usable size');
  return entry.size;
}

async function readConsoleFile(shell, path, cap) {
  const files = shell.requireFiles('cat');
  const size = await fileSize(shell, 'cat', path);
  if (size > cap) throw fail('E_ARGS', 'file is ' + size + ' bytes — over the ' +
    cap + ' cat cap; use get <path> <local> instead');
  const parts = [];
  for (let at = 0; at < size; at += FILE_CHUNK) {
    const length = Math.min(FILE_CHUNK, size - at);
    const bytes = await files.read(path, at, length);
    if (!Buffer.isBuffer(bytes) || bytes.length !== length) throw fail('E_PROTOCOL',
      'file session read() returned ' + (bytes?.length ?? bytes) + ' of ' + length + ' bytes');
    parts.push(bytes);
  }
  return Buffer.concat(parts);
}

async function getConsoleFile(shell, path, local) {
  const files = shell.requireFiles('get');
  const size = await fileSize(shell, 'get', path);
  const output = await openLocalOutput(local);
  const digest = crypto.createHash('sha256');
  let at = 0;
  try {
    for (; at < size; at += FILE_CHUNK) {
      const length = Math.min(FILE_CHUNK, size - at);
      const bytes = await files.read(path, at, length);
      if (!Buffer.isBuffer(bytes) || bytes.length !== length) throw fail('E_PROTOCOL',
        'file session read() returned ' + (bytes?.length ?? bytes) + ' of ' + length + ' bytes');
      await output.write(bytes);
      digest.update(bytes);
    }
    await output.sync();
  } finally {await output.close();}
  return {text: 'wrote ' + at + ' bytes to ' + local + ' (sha256 ' +
    digest.digest('hex').slice(0, 16) + '…)', length: at, local};
}

async function putLocalFile(shell, local, path) {
  const files = shell.requireFiles('put');
  if (typeof local !== 'string' || !local.length || local.includes('\0'))
    throw fail('E_ARGS', 'Invalid local path');
  const bytes = await fs.readFile(local); // ENOENT surfaces as the host errno
  if (bytes.length > 0x10000000) throw fail('E_ARGS', 'local file exceeds 256 MiB');
  const chunks = Math.max(1, Math.ceil(bytes.length / FILE_CHUNK));
  for (let index = 0; index < chunks; index++) {
    const at = index * FILE_CHUNK;
    try {await files.write(path, at, bytes.subarray(at, at + FILE_CHUNK));}
    catch (error) {throw withCode(error, 'E_TRANSPORT');}
  }
  return {text: 'put ' + bytes.length + ' bytes to ' + path, length: bytes.length};
}

async function openLocalOutput(local) {
  if (typeof local !== 'string' || !local.length || local.includes('\0'))
    throw fail('E_ARGS', 'Invalid local path');
  try {
    return await fs.open(local, 'wx', 0o600); // never clobber an existing file
  } catch (error) {
    if (error.code === 'EEXIST') throw fail('E_ARGS', 'local file exists: ' + local);
    if (error.code === 'EISDIR' || error.code === 'ENOENT')
      throw fail('E_ARGS', 'local path is not writable: ' + local);
    throw error;
  }
}

async function bisProbe(shell, id) {
  const probe = await shell.fsRequest('bis-ls', {command: 'root-probe-bis', id});
  if (probe.result) throw fail('E_VERIFY', 'OpenBisStorage(' + id + ') failed: 0x' +
    Number(probe.result).toString(16));
  const size = BigInt(probe.size ?? 0);
  if (size <= 0n) throw fail('E_PROTOCOL', 'BIS ' + id + ' reported no size');
  return {id, size};
}

async function bisListing(shell, ids) {
  const rows = [];
  for (const id of ids) {
    const partition = await bisProbe(shell, id);
    rows.push(('bis:' + id).padEnd(10) +
      (id === 30 ? 'USER' : id === 31 ? 'SYSTEM' : '?').padEnd(8) +
      partition.size.toString().padStart(16));
  }
  return {text: 'storage   kind    bytes\n' + rows.join('\n') +
    '\n(raw storage — bis-get reads ranges; no directory layer in v1)'};
}

async function bisGet(shell, id, offset, length, local) {
  const partition = await bisProbe(shell, id);
  if (offset + length > partition.size) throw fail('E_ARGS',
    'range ' + hex(offset) + '+' + hex(length) + ' exceeds BIS ' + id +
    ' size ' + partition.size);
  const output = await openLocalOutput(local);
  const digest = crypto.createHash('sha256');
  let at = 0n;
  try {
    for (; at < length; at += BigInt(BIS_CHUNK)) {
      const n = Number(length - at > BigInt(BIS_CHUNK) ? BigInt(BIS_CHUNK) : length - at);
      const read = await shell.fsRequest('bis-get',
        {command: 'root-read-bis', id, offset: Number(offset + at), length: n});
      if (read.length !== n || typeof read.outputFile !== 'string' || !read.sha256)
        throw fail('E_PROTOCOL', 'root-read-bis returned a malformed reply');
      const bytes = await fs.readFile(read.outputFile);
      if (bytes.length !== n || crypto.createHash('sha256').update(bytes).digest('hex') !== read.sha256)
        throw fail('E_VERIFY', 'BIS chunk ' + hex(offset + at) + ' failed its sha256 check');
      await output.write(bytes);
      digest.update(bytes);
    }
    await output.sync();
  } finally {await output.close();}
  return {text: 'wrote ' + at + ' bytes from bis:' + id + ' to ' + local +
    ' (sha256 ' + digest.digest('hex').slice(0, 16) + '…)', length: Number(at)};
}

async function storageReport(shell) {
  shell.requireFs('df');
  const lines = ['storage            free               total'];
  let saveReported = false;
  if (shell.fsEndpoint.files?.df) {
    const usage = await shell.fsEndpoint.files.df();
    if (!Number.isSafeInteger(usage?.free) || !Number.isSafeInteger(usage?.total))
      throw fail('E_PROTOCOL', 'file session df() returned a malformed report');
    lines.push('save:'.padEnd(18) + String(usage.free).padStart(18) +
      String(usage.total).padStart(19));
    saveReported = true;
  }
  const root = await shell.fsRequest('df', {command: 'root-info'});
  for (const storage of root.storages || []) {
    const partition = await bisProbe(shell, storage.id);
    lines.push(('bis:' + storage.id).padEnd(18) + '-'.padStart(18) +
      partition.size.toString().padStart(19));
  }
  if (!saveReported && !(root.storages || []).length)
    lines.push('(no storage connected — save session pending, no BIS probed)');
  return {text: lines.join('\n')};
}

async function mountInfo(shell) {
  const lines = [];
  lines.push('bridge (civshim, game process): ' + (shell.bridge ?
    'connected (' + shell.calls + ' shell ops)' :
    'NOT CONNECTED — M1: send payloads/civshim.js and connect'));
  if (shell.fsEndpoint) {
    const info = await shell.fsRequest('mount-info', {command: 'info'});
    const root = await shell.fsRequest('mount-info', {command: 'root-info'});
    lines.push('fs endpoint (memory.sock): ' + (info.ready ? 'ready' : 'not ready') +
      ', session ' + (info.session ?? '?'));
    lines.push('  PID 1 fsp-srv root: ' + (root.initialized ? 'initialized' :
      'not initialized') + ', ' + (root.clones || []).length + ' clone(s)');
    lines.push('  BIS storages: [' + ((root.storages || []).map(s => s.id).join(', ') || '-') +
      ']  filesystems: [' + ((root.filesystems || []).map(s => s.id).join(', ') || '-') + ']');
    lines.push('  save session (files): ' + (shell.fsEndpoint.files ?
      'connected' : 'NOT WIRED — pending Civ 7 port of switch2/app/mounted-save.cjs'));
  } else lines.push('fs endpoint: NOT CONNECTED — run --stage acquire first');
  if (shell.roClient) {
    lines.push('ro payload (ro:dmnt 0x524F00xx): connected, pid ' +
      (shell.roClient.pid ?? '?') + ', handle 0x' + Number(shell.roClient.handle ?? 0).toString(16));
    lines.push('  processHandle(): ' + (typeof shell.roClient.processHandle === 'function' ?
      'wired' : 'NOT WIRED — proc-*/exec-map targets cannot resolve (docs/SHELL.md)'));
    lines.push('  processes(): ' + (typeof shell.roClient.processes === 'function' ?
      'wired (full ps)' : 'not wired — ps shows session rows only'));
  } else lines.push('ro payload: NOT CONNECTED — run --stage launch first');
  return {text: lines.join('\n')};
}

// ---- ro helpers -------------------------------------------------------------------

async function processList(shell) {
  const ro = shell.requireRo('ps');
  if (typeof ro.processes === 'function') {
    let rows;
    try {rows = await ro.processes();}
    catch (error) {throw withCode(error, 'E_TRANSPORT');}
    if (!Array.isArray(rows)) throw fail('E_PROTOCOL', 'processes() returned a malformed list');
    const lines = ['pid'.padEnd(14) + 'program'.padEnd(20) + 'name'];
    for (const row of rows) {
      if (row === null || typeof row !== 'object' || row.pid === undefined)
        throw fail('E_PROTOCOL', 'processes() returned a malformed row');
      lines.push(String(row.pid).padEnd(14) +
        String(row.programId ?? '-').padEnd(20) + (row.name ?? '-'));
    }
    return {text: lines.join('\n'), rows};
  }
  // Fallback: what this shell itself can name. Still real data (RO identity).
  const lines = ['pid'.padEnd(14) + 'program'.padEnd(20) + 'name',
    String(ro.pid ?? '-').padEnd(14) + '0x0400000000000037  ro payload (this shell\'s server)'];
  if (shell.bridge) lines.push(String('-').padEnd(14) + 'Civ 7 game'.padEnd(20) +
    'bridge target (pid via the wiring processHandle())');
  lines.push('', 'full enumeration needs roClient.processes() (pm:dmnt + RO 0x524F0010;',
  'see docs/SHELL.md "wiring contract")');
  return {text: lines.join('\n')};
}

async function procRead(ro, handle, pid, address, length) {
  if (typeof ro.bulkRead === 'function') {
    // The documented 0x524F0016 path: one receive-window read, <= 4 MiB.
    const reply = await ro.bulkRead(handle, pid, address, length);
    const bytes = Buffer.isBuffer(reply?.bytes) ? reply.bytes :
      typeof reply?.hex === 'string' ? Buffer.from(reply.hex, 'hex') : null;
    if (reply?.result || !bytes || bytes.length !== Number(length))
      throw fail('E_PROTOCOL', 'RO 0x524F0016 read failed: 0x' +
        Number(reply?.result ?? 0).toString(16));
    return finishProcRead(pid, address, bytes);
  }
  // Fallback: the hardware-proven 0x524F0011 path, 128 B per page-bounded
  // chunk. Kept for wirings without a receive-buffer helper; capped so one
  // command stays well inside the anti-spiral budget.
  if (length > BigInt(CHUNK_READ_CAP)) throw fail('E_ARGS',
    'len ' + length + ' needs the 0x524F0016 bulk path (roClient.bulkRead is not' +
      ' wired); the 0x524F0011 fallback is capped at 0x' + CHUNK_READ_CAP.toString(16));
  if (typeof ro.read !== 'function') throw fail('E_CONFIG',
    'roClient provides neither bulkRead (0x524F0016) nor read (0x524F0011)');
  const parts = [];
  for (let at = 0n; at < length;) {
    const page = 0x1000n - ((address + at) & 0xfffn); // 0x524F0011 stays in one page
    const bound = page < 128n ? page : 128n;
    const n = Number(bound < length - at ? bound : length - at);
    const reply = await ro.read(handle, pid, address + at, n);
    if (reply.result || !reply.hex) throw fail('E_PROTOCOL',
      'RO 0x524F0011 read failed: 0x' + Number(reply.result ?? 0).toString(16));
    const bytes = Buffer.from(reply.hex, 'hex');
    if (bytes.length !== n) throw fail('E_PROTOCOL', 'RO read chunk was short');
    parts.push(bytes);
    at += BigInt(n);
  }
  return finishProcRead(pid, address, Buffer.concat(parts));
}

function finishProcRead(pid, address, bytes) {
  const text = bytes.length <= READ_CAP ? hexdump(address, bytes) :
    hexdump(address, bytes.subarray(0, 64)) + '\n… ' + (bytes.length - 64) +
    ' more bytes (dataHex carries the full buffer)';
  return {text, dataHex: bytes.toString('hex'), address: address.toString(),
    length: bytes.length, pid: String(pid)};
}

async function procPatch(ro, handle, pid, address, replacement) {
  if (typeof ro.patch !== 'function') throw fail('E_CONFIG',
    'roClient.patch (0x524F0014) is not wired');
  // The primitive is compare-and-swap: read the current 16 bytes first and
  // hand them in as the expected value, so a racing change fails loudly
  // instead of patching stale ground truth.
  const current = await procRead(ro, handle, pid, address, 16n);
  const expected = Buffer.from(current.dataHex, 'hex');
  const reply = await ro.patch(handle, pid, address, expected, replacement);
  if (reply.result) throw fail('E_PROTOCOL',
    'RO patch failed: 0x' + Number(reply.result).toString(16));
  if (!reply.expectedMatched) throw fail('E_VERIFY',
    'expected bytes changed under us — nothing was written; retry');
  if (!reply.readbackMatched) throw fail('E_VERIFY',
    'patch readback differs — the write may be partially live; inspect before retry');
  return {text: 'patched ' + hex(address) + ' in pid ' + pid + '\n  before ' +
    expected.toString('hex') + '\n  after  ' + replacement.toString('hex'),
    address: address.toString(), pid: String(pid)};
}

module.exports = {Shell, tokenize, hexdump, COMMANDS, SUBSYSTEMS,
  READ_CAP, WRITE_CAP, FILE_CHUNK, CAT_CAP, BIS_CHUNK, BULK_READ_CAP};
