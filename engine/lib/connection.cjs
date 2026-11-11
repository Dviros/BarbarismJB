// engine/lib/connection.cjs — host side of the civshim transport: connect out
// to the console, parse and validate the CIV1 hello.
//
// Purpose: replace the SmileBASIC DSC1 pairing listener from ns2jb with a
// direction-inverted client — civshim.js (inside the Civ 7 process) listens
// on TCP :39381 and the HOST connects to it. On accept the console sends a
// 128-byte CIV1 hello plus a 256-byte JSON offsets trailer. Downstream
// consumers keep the ns2jb session-init shape: {connection, addresses} with
// a live Connection implementing read/write/close under the
// never-replay-after-timeout discipline.
// Protocol: payloads/civshim.js header comment + README.md "The civshim wire
// protocol". Errors carry E_PROTOCOL / E_TIMEOUT / E_TRANSPORT codes.
// Origin: ported from ns2jb engine/lib/connection.cjs (SmileBASIC pairing
// listener), heavily adapted for BarbarismJB — see `// barbarism:` markers.
const net = require('node:net');
const {fail, withCode} = require('../shared/errors.cjs');

// barbarism: hello geometry (identical framing constants as the console side).
const HELLO_BYTES = 128;
const TRAILER_BYTES = 256;
const MAGIC = 0x31564943;          // wire bytes read "CIV1"
const VERSION = 1;
const PLATFORM = 2;

// TCP may split a record anywhere. A timeout ends the connection; requests
// cannot be replayed because a native operation might already have completed.
class Connection {
  constructor(socket, timeout = 180000) {
    this.socket = socket;
    this.timeout = timeout;
    this.buffer = Buffer.alloc(0);
    socket.setNoDelay(true);
    socket.on('data', bytes => {
      this.buffer = Buffer.concat([this.buffer, bytes]);
      if (this.buffer.length > 0x100000) this.fail(Error('Unexpected console output'));
      this.drain();
    });
    socket.on('error', error => this.fail(error));
    socket.on('end', () => this.fail(Error('Console disconnected')));
    socket.on('close', () => this.fail(Error('Console connection closed')));
  }

  fail(error) {
    this.error ||= withCode(error, 'E_TRANSPORT');
    if (this.pending) {
      clearTimeout(this.pending.timer);
      this.pending.reject(this.error);
      this.pending = null;
    }
    this.socket.destroy();
  }

  drain() {
    const pending = this.pending;
    if (!pending || this.buffer.length < pending.size) return;
    const bytes = this.buffer.subarray(0, pending.size);
    this.buffer = this.buffer.subarray(pending.size);
    clearTimeout(pending.timer);
    this.pending = null;
    pending.resolve(bytes);
  }

  read(size) {
    if (!Number.isSafeInteger(size) || size < 1 || size > 0x100000)
      return Promise.reject(fail('E_PROTOCOL', 'Invalid response length'));
    if (this.error) return Promise.reject(this.error);
    if (this.pending) return Promise.reject(fail('E_PROTOCOL', 'A console response is already pending'));
    return new Promise((resolve, reject) => {
      // barbarism: 180s discipline — a native call (pthread_join, long IPC) may
      // legitimately block for a while, but after this the session is dead and
      // must never be replayed.
      const timer = setTimeout(() => this.fail(fail('E_TIMEOUT',
        'Console response timed out; restart the application')), this.timeout);
      this.pending = {size, resolve, reject, timer};
      this.drain();
    });
  }

  write(bytes) {
    if (this.error) return Promise.reject(this.error);
    return new Promise((resolve, reject) => {
      this.socket.write(bytes, error => {
        if (error) {this.fail(error); reject(error);}
        else resolve();
      });
    });
  }

  close() { this.fail(Error('Connection closed')); }
}

// barbarism: parse the 128-byte CIV1 header + 256-byte JSON trailer (layout in
// payloads/civshim.js: four u32 words — magic, version, platform, reserved —
// then ten u64 fields starting at offset 16). Bases must be present and
// plausible; unknown svc wrappers are carried as 0 and reported — features
// that need them fail loudly at use time (see lib/offsets.cjs).
function parseHello(header, trailer) {
  if (header.length !== HELLO_BYTES) throw fail('E_PROTOCOL', 'Incomplete console greeting');
  if (header.readUInt32LE(0) !== MAGIC || header.readUInt32LE(4) !== VERSION ||
      header.readUInt32LE(8) !== PLATFORM)
    throw fail('E_PROTOCOL', 'Wrong civshim protocol, version, or console type');
  if (header.readUInt32LE(12) !== 0) throw fail('E_PROTOCOL', 'Console greeting reserved word is not zero');
  const u64 = offset => header.readBigUInt64LE(offset);
  const values = {
    main: u64(16), mainSize: u64(24), sdk: u64(32), sdkSize: u64(40),
    scratch: u64(48), scratchBytes: u64(56),
    svcQueryMemory: u64(64), svcSendSyncRequest: u64(72),
    svcConnectToNamedService: u64(80), svcSleepThread: u64(88)
  };
  for (const [name, value] of Object.entries(values))
    if (value > BigInt(Number.MAX_SAFE_INTEGER))
      throw fail('E_PROTOCOL', 'Console greeting contains an imprecise address: ' + name);
  const addresses = {};
  for (const name of ['main', 'sdk', 'scratch']) {
    const value = Number(values[name]);
    if (value < 0x1000 || value >= 2 ** 39 || value % 4096)
      throw fail('E_PROTOCOL', 'Invalid Civ 7 module or scratch address: ' + name);
    addresses[name] = value;
  }
  addresses.mainSize = Number(values.mainSize);
  addresses.sdkSize = Number(values.sdkSize);
  if (addresses.mainSize >= 2 ** 39 || addresses.sdkSize >= 2 ** 39)
    throw fail('E_PROTOCOL', 'Implausible module size in greeting');
  addresses.scratchBytes = Number(values.scratchBytes);
  if (addresses.scratchBytes <= 0 ||
      BigInt(addresses.scratch) + BigInt(addresses.scratchBytes) >= 2n ** 39n)
    throw fail('E_PROTOCOL', 'Invalid civshim scratch buffer');
  const addresses64 = {
    query_memory: values.svcQueryMemory,
    send_sync_request: values.svcSendSyncRequest,
    connect_to_named_service: values.svcConnectToNamedService,
    sleep_thread: values.svcSleepThread
  };
  for (const [name, value] of Object.entries(addresses64))
    if (value !== 0n && (value < 0x1000n || value >= 2n ** 39n || value % 4n))
      throw fail('E_PROTOCOL', 'Invalid svc wrapper address in greeting: ' + name);
  addresses.svc = Object.fromEntries(Object.entries(addresses64).map(([name, value]) => [name, Number(value)]));
  let dict = {};
  const text = trailer.toString('utf8').split('\0')[0].trim();
  if (text) {
    try {dict = JSON.parse(text);}
    catch {throw fail('E_PROTOCOL', 'Console offsets trailer is not valid JSON');}
    if (!dict || typeof dict !== 'object' || Array.isArray(dict)) throw fail('E_PROTOCOL', 'Console offsets trailer is not an object');
  }
  return {...addresses, platform: PLATFORM, offsets: dict};
}

// barbarism: replaces ns2jb listen() — the host connects out to civshim :39381.
async function connect({host, port, timeout = 30 * 1000, helloTimeout = 10 * 1000}) {
  if (!net.isIPv4(host)) throw fail('E_USAGE', 'Expected the console\u2019s LAN IPv4 address');
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw fail('E_USAGE', 'Port must be 1024..65535');
  const socket = await new Promise((resolve, reject) => {
    const attempt = net.connect({host, port});
    const timer = setTimeout(() => {
      attempt.destroy();
      reject(fail('E_TRANSPORT', `No civshim listener at ${host}:${port}. Send payloads/civshim.js through the CivSwitch :9026 loader first.`));
    }, timeout);
    attempt.once('connect', () => {clearTimeout(timer); resolve(attempt);});
    attempt.once('error', error => {
      clearTimeout(timer);
      reject(fail('E_TRANSPORT', `Cannot reach civshim at ${host}:${port} (${error.code || error.message}). Is the game running with the shim loaded?`));
    });
  });
  const connection = new Connection(socket, helloTimeout);
  try {
    const header = await connection.read(HELLO_BYTES);
    const trailer = await connection.read(TRAILER_BYTES);
    connection.timeout = 180000;
    return {connection, addresses: parseHello(header, trailer)};
  } catch (error) {
    connection.close();
    throw error;
  }
}

module.exports = {Connection, HELLO_BYTES, TRAILER_BYTES, MAGIC, parseHello, connect};
