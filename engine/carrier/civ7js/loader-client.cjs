// engine/carrier/civ7js/loader-client.cjs — host-side client for the CivSwitch
// Remote JS Loader (TCP :9026 inside the Civ 7 process).
//
// Purpose: push a JS payload into the loader and stream back its log output —
// the Node equivalent of the civswitch-kit's save-tools/send_js.py and
// Gezine's send_js.py. Wire behavior (kit:save-tools/send_js.py:18-33 and
// kit:docs/BRIDGE-CONTRACT.md): connect, send the payload bytes, then
// HALF-CLOSE the write side (the loader reads until EOF), and keep reading
// the loader's log stream until it closes the connection or goes idle.
//
// Discipline carried over from the kit's field notes (kit:README.md §8,
// kit:docs/PORT-HANDOFF.md §2): empty connects to :9026 count as "bad
// connections" — three of them make the loader rebuild its listener — so this
// client never opens a connection without a payload to send, and exposes no
// "probe" mode. Use the log stream (or the :39381 civshim listener) to detect
// liveness instead.
//
// Origin: original — BarbarismJB; wire behavior documented from the
// GPL-2.0 civswitch-kit (provenance in PROVENANCE.md).
// Docs: docs/CIVSWITCH-INTEGRATION.md §1, docs/CIVSWITCH-RUNBOOK.md.
'use strict';
const net = require('node:net');

const DEFAULT_PORT = 9026;
const DEFAULT_CONNECT_TIMEOUT_MS = 8000;   // kit send_js.py connect timeout
const DEFAULT_IDLE_TIMEOUT_MS = 120000;    // kit send_js.py read timeout

// Errors carry a `code` field: E_LOADER_CONNECT | E_LOADER_CLOSED | E_LOADER_PROTOCOL.
function fail(code, message) {
  return Object.assign(Error('loader: ' + message), {code});
}

// Send `payload` (string or Buffer) to the loader at host:port and collect the
// log lines it streams back. Resolves {logs, bytes} once the loader closes the
// connection or the idle timeout lapses (long-running payloads like civshim
// never close the stream — for those pass onLog and a short idleTimeoutMs, or
// use waitFor()). Never rejects on log content; rejects only on connect
// failure or a socket error before the payload is fully written.
function sendPayload({host, port = DEFAULT_PORT, payload, connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS,
    idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS, onLog = null}) {
  if (net.isIPv4(host) === false && net.isIPv6(host) === false)
    return Promise.reject(fail('E_ARGS', 'expected the console\u2019s IP address'));
  if (!Number.isInteger(port) || port < 1024 || port > 65535)
    return Promise.reject(fail('E_ARGS', 'port must be 1024..65535'));
  const bytes = Buffer.isBuffer(payload) ? payload : Buffer.from(payload == null ? '' : String(payload), 'utf8');
  if (!bytes.length) return Promise.reject(fail('E_ARGS', 'refusing an empty payload (empty connects are counted as bad connections by the loader)'));
  return new Promise((resolve, reject) => {
    const socket = net.connect({host, port});
    let settled = false, written = false, chunks = [];
    let idle;
    const finish = (error, early) => {
      if (settled) return;
      settled = true;
      clearTimeout(idle);
      socket.destroy();
      if (error) reject(error);
      else resolve({logs: Buffer.concat(chunks).toString('utf8'), bytes: bytes.length, closedEarly: Boolean(early)});
    };
    const armIdle = () => {
      clearTimeout(idle);
      idle = setTimeout(() => finish(null, true), idleTimeoutMs);
    };
    socket.setTimeout(connectTimeoutMs);
    socket.once('timeout', () => finish(fail('E_LOADER_CONNECT',
      'connect timeout after ' + connectTimeoutMs + ' ms (is the loader armed? screen should show "Awaiting payload at ' + host + ':' + port + '")')));
    socket.once('error', error => finish(fail(written ? 'E_LOADER_CLOSED' : 'E_LOADER_CONNECT',
      (written ? 'loader stream failed: ' : 'cannot reach the loader: ') + (error.code || error.message))));
    socket.once('connect', () => {
      socket.setTimeout(0);
      socket.write(bytes, error => {
        if (error) {finish(fail('E_LOADER_PROTOCOL', 'payload write failed: ' + (error.code || error.message))); return;}
        written = true;
        // Half-close: the loader evaluates the payload once the client shuts
        // down its write side. Its log stream keeps flowing afterwards.
        socket.end();
        armIdle();
      });
    });
    socket.on('data', chunk => {
      chunks.push(chunk);
      if (chunks.reduce((n, c) => n + c.length, 0) > 4 * 1024 * 1024) {
        finish(fail('E_LOADER_PROTOCOL', 'loader log stream exceeded 4 MiB'));
        return;
      }
      if (onLog) {
        try {onLog(chunk.toString('utf8'));}
        catch { /* a logging callback must never kill the transfer */ }
      }
      armIdle();
    });
    socket.once('close', () => {if (written) finish(null, false);});
  });
}

// Deploy helper: send the payload and wait until the log stream shows one of
// `markers` (e.g. civshim's "civshim: listening on :39381"). Resolves as soon
// as the marker is seen (the stream keeps running in the background until the
// idle timeout — long-running payloads never close it). Rejects with the
// collected log if the stream ends first.
async function sendAndAwait({host, port, payload, markers, connectTimeoutMs, idleTimeoutMs = 30000, log = null}) {
  const wanted = markers.map(marker => String(marker));
  let seen = null;
  const result = await sendPayload({
    host, port, payload, connectTimeoutMs, idleTimeoutMs,
    onLog: text => {
      if (log) log(text);
      if (!seen) for (const marker of wanted)
        if (text.includes(marker)) {seen = marker; break;}
    }
  });
  if (!seen)
    throw fail('E_LOADER_CLOSED', 'the loader stream closed without any marker line [' +
      wanted.join(' | ') + ']; last output:\n' + tail(result.logs, 2000));
  return {...result, marker: seen};
}

function tail(text, bytes) {
  return text.length <= bytes ? text : '\u2026' + text.slice(-bytes);
}

module.exports = {sendPayload, sendAndAwait, DEFAULT_PORT};
