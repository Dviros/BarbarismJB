// engine/shared/errors.cjs — BarbarismJB error taxonomy, defined exactly once.
//
// Every first-party host-side failure carries a stable `error.code` from the
// table below so callers (run.cjs, pipeline children, tests) can branch on
// the class of failure instead of parsing message strings. CLI exit-code
// mapping lives in run.cjs: E_USAGE -> 2, everything else -> 1.
//
// The console-side wire statuses (payloads/civshim.js STATUS) are mirrored
// here as PROTOCOL_STATUS for host-side tests and documentation; the console
// keeps its own copy because it runs inside the loader closure without
// require().
//
// Origin: original — BarbarismJB 0.1.0.

const CODES = Object.freeze({
  // CLI usage errors (bad flags, missing arguments) — exit code 2.
  E_USAGE: 'E_USAGE',
  // Invalid runtime arguments to a builder/API (worker frames, spans).
  E_ARGS: 'E_ARGS',
  // Wire-protocol violations: bad magic, framing mismatch, malformed frame.
  E_PROTOCOL: 'E_PROTOCOL',
  // A response did not arrive inside the timeout budget. Never replay.
  E_TIMEOUT: 'E_TIMEOUT',
  // Socket-level failure or remote disconnect.
  E_TRANSPORT: 'E_TRANSPORT',
  // offsets/civ7-100.json missing, unparsable, incomplete, or contradicting
  // the live CIV1 hello.
  E_OFFSETS: 'E_OFFSETS',
  // Environment knob or run-configuration value rejected.
  E_CONFIG: 'E_CONFIG',
  // A subsystem still awaiting its Civ 7 port (unported() guard).
  E_UNPORTED: 'E_UNPORTED',
  // An end-to-end verification step failed (round-trip, pin, read-back).
  E_VERIFY: 'E_VERIFY',
  // Anything that should not happen — bug, not an operational condition.
  E_INTERNAL: 'E_INTERNAL'
});

// civshim response statuses (see payloads/civshim.js and README.md):
// 0 ok, 1 op-unavailable (offset unknown on-console), 2 op-failed (native
// call returned an error), 3 bad request, 4 internal error.
const PROTOCOL_STATUS = Object.freeze({OK: 0, UNAVAILABLE: 1, FAILED: 2, BAD_REQUEST: 3, INTERNAL: 4});

// Build a coded Error. Message is always actionable text; code is machine
// readable. Returns the Error (throws at the call site).
function fail(code, message) {
  if (!CODES[code]) throw Error('Unknown error code: ' + code);
  return Object.assign(Error(message), {code});
}

// Attach a code to an existing Error without rewriting its message.
function withCode(error, code) {
  if (!CODES[code]) throw Error('Unknown error code: ' + code);
  if (error && !error.code) error.code = code;
  return error;
}

module.exports = {CODES, PROTOCOL_STATUS, fail, withCode};
