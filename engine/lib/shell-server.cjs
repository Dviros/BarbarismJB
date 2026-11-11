// engine/lib/shell-server.cjs — loopback TCP/JSON front for the BarbarismJB
// shell (M5, v1).
//
// Purpose: expose one Shell instance (engine/lib/shell.cjs) to
// tools/shell_client.py (and scripts) over newline-delimited JSON on a
// loopback-only TCP listener, with the same discipline engine/lib/bridge.cjs
// serve() applies to the civshim connection:
//   - serialized queue — one shell command in flight at a time; concurrent
//     clients wait their turn (a native op must never interleave);
//   - 180 s per-command budget — on timeout the requesting socket is
//     destroyed AND the front is poisoned: a native op may already have
//     completed, so nothing is ever replayed. Later commands fail fast with
//     E_TIMEOUT instead of racing the possibly-live op;
//   - no authentication, no broadcast — 127.0.0.1 only (checked on bind);
//     anything that can reach the port already owns the machine, which is
//     also why there is deliberately no auth to get wrong;
//   - coded errors — every failure reply carries a code from
//     engine/shared/errors.cjs; uncoded errors become E_INTERNAL.
//
// Protocol (one request per line, one reply per request, UTF-8):
//   request  {"line": "read64 0x7100000000"}
//   reply    {"ok": true, "text": "0x…", ...command extras}
//         or {"ok": false, "code": "E_ARGS", "error": "usage: read64 <addr>"}
//   The "exit" command replies {"ok": true, "exit": true} and the server
//   closes that client's connection; the shell itself stays up.
//
// Origin: original — BarbarismJB M5. Docs: docs/SHELL.md (intended run.cjs
// --shell [port] wiring, security notes).
'use strict';
const net = require('node:net');
const {withCode} = require('../shared/errors.cjs');

const DEFAULT_TIMEOUT_MS = 180000; // one shell command, matching the bridge budget
const MAX_LINE = 1 << 20;          // request line cap (hex dumps arrive as text)
const LOOPBACK = '127.0.0.1';

// The socket-free core: serializes commands, applies the timeout budget and
// the never-replay poisoning. serve() drives it per line; the offline sim
// (tests/shell-sim.cjs) drives it directly with no sockets at all.
class Front {
  constructor(shell, {timeoutMs = DEFAULT_TIMEOUT_MS, log = null} = {}) {
    if (!shell) throw Error('shell-server requires a Shell instance');
    this.shell = shell;
    this.timeoutMs = timeoutMs;
    this.log = log || {debug() {}, info() {}, warn() {}, error() {}};
    this.queue = Promise.resolve();
    this.poisoned = null;
    this.served = 0;
  }

  enqueue(task) {
    const result = this.queue.then(task, task);
    this.queue = result.catch(() => {});
    return result;
  }

  // Run one command line through the serialized queue. Always RESOLVES to a
  // protocol reply object — coded failures included — so a socket handler
  // never has to second-guess serialization.
  command(line) {
    return this.enqueue(() => this.run(line));
  }

  async run(line) {
    if (this.poisoned) return this.poisonedReply();
    let timer = null;
    try {
      const budget = new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(
          Error('shell command timed out after ' + this.timeoutMs + ' ms; the native' +
            ' operation may already have completed — nothing is replayed'),
          {code: 'E_TIMEOUT', timedOut: true})), this.timeoutMs);
      });
      const result = await Promise.race([this.shell.execute(line), budget]);
      this.served++;
      if (result.exit) this.log.info('shell session ended by exit');
      return stringify(result);
    } catch (error) {
      const coded = withCode(error instanceof Error ? error : Error(String(error)),
        'E_INTERNAL');
      if (coded.timedOut || coded.code === 'E_TIMEOUT' || coded.code === 'E_TRANSPORT') {
        // Never-replay discipline: a native op may still be in flight. Poison
        // the front so later commands cannot interleave with it.
        this.poisoned = coded.code;
        this.log.error('shell front poisoned (%s): %s', coded.code, coded.message);
      } else this.log.warn('shell command failed (%s): %s', coded.code, coded.message);
      return {ok: false, code: coded.code, error: coded.message};
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  poisonedReply() {
    return {ok: false, code: 'E_TIMEOUT', error: 'the shell was poisoned by a' +
      ' timeout/transport failure — a native operation may still be in flight.' +
      ' Nothing is replayed; start a new shell session (run.cjs --shell).'};
  }
}

function stringify(result) {
  // BigInts never ride JSON; every command returns string-safe fields.
  return JSON.parse(JSON.stringify(result, (_, value) =>
    typeof value === 'bigint' ? value.toString() : value));
}

// Bind the loopback listener. shell: Shell; options: {port = 0 (ephemeral),
// host = '127.0.0.1', timeoutMs, log}. Resolves {port, host, front, close()}.
async function serve(shell, options = {}) {
  const host = options.host || LOOPBACK;
  if (host !== LOOPBACK && host !== 'localhost')
    throw Error('shell-server binds loopback only (got ' + host + ')');
  const front = new Front(shell, {timeoutMs: options.timeoutMs, log: options.log});
  const sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.setEncoding('utf8');
    let buffer = '';
    socket.on('error', () => socket.destroy());
    socket.on('data', chunk => {
      buffer += chunk;
      if (buffer.length > MAX_LINE) {
        reply(socket, {ok: false, code: 'E_ARGS', error: 'request line exceeds 1 MiB'});
        socket.destroy();
        return;
      }
      let at;
      while ((at = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, at);
        buffer = buffer.slice(at + 1);
        handle(front, socket, line);
      }
    });
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port || 0, LOOPBACK, resolve);
  });
  const port = server.address().port;
  front.log.info('shell server listening on 127.0.0.1:%d', port);
  return {
    port, host: LOOPBACK, front,
    async close() {
      for (const socket of sockets) socket.destroy();
      sockets.clear();
      await new Promise(resolve => server.close(resolve));
      await front.queue; // let an in-flight command settle before returning
    },
  };
}

// One request line -> one reply. The reply for `exit` is sent first, then the
// client connection ends; a poisoned front still answers (fast-fail).
async function handle(front, socket, line) {
  const text = line.trim();
  if (!text) {reply(socket, {ok: false, code: 'E_ARGS', error: 'empty request'}); return;}
  let request;
  try {request = JSON.parse(text);}
  catch {reply(socket, {ok: false, code: 'E_ARGS', error: 'request is not valid JSON'}); return;}
  if (!request || typeof request !== 'object' || Array.isArray(request) ||
      typeof request.line !== 'string')
    {reply(socket, {ok: false, code: 'E_ARGS',
      error: 'expected {"line": "<command>"}'}); return;}
  const response = await front.command(request.line);
  reply(socket, response);
  if (response.exit) socket.end();
}

function reply(socket, response) {
  if (!socket.destroyed) socket.write(JSON.stringify(response) + '\n');
}

module.exports = {serve, Front, DEFAULT_TIMEOUT_MS, MAX_LINE};
