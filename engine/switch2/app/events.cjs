// Manual-reset light events stored entirely in our allocation.
// barbarism: PORTED to the offsets table (was: SmileBASIC event-code.json
// instruction pins behind a loud unported() guard). The five nn::os event
// wrappers the wave's gate/cancel path needs (worker start gates, the ro
// notifier workers' gates) now resolve from sdk_offsets.event_* entries in
// offsets/civ7-100.json — M0 RE locates them in Civ 7's nnSdk (same nn::os
// API surface the SmileBASIC table fingerprinted; reference offsets in the
// template notes). `code` keeps the upstream sdk-relative {offset} shape the
// consumers use directly (memory/probe-reserved-gap.cjs wait/signal calls,
// ro/worker-control.cjs gates, app/qualify.cjs). Backends:
//   ropchain (default) — presence + executable-mapping check; the offsets
//     table's module pins (first_page_sha256/region hashes) are the identity.
//   frames — the original byte pins via event-code.json, still SmileBASIC
//     fingerprints; re-fingerprint that table for Civ 7 before using it.
const {live, check} = require("./session.cjs");
const nativeOffsets = require('./native-offsets.cjs');
const config = require("../../shared/config.cjs");
const framesCode = require("./event-code.json").functions;

// barbarism: built like worker.cjs ropchainCode — null until the offsets table
// carries the key; verify() fails loudly naming it before any wave can run.
const offsetsCode = {
  initialize: {offset: nativeOffsets.optionalSdkOffset(live, 'event_initialize')},
  signal: {offset: nativeOffsets.optionalSdkOffset(live, 'event_signal')},
  clear: {offset: nativeOffsets.optionalSdkOffset(live, 'event_clear')},
  finalize: {offset: nativeOffsets.optionalSdkOffset(live, 'event_finalize')},
  wait: {offset: nativeOffsets.optionalSdkOffset(live, 'event_wait')}
};
const code = config.workerBackend() === 'frames' ? framesCode : offsetsCode;

async function verify(s) {
  if (config.workerBackend() === 'frames') {
    for (const [name, expected] of Object.entries(code))
      await s.verifyCode(expected, 'Event ' + name);
    return;
  }
  for (const name of ['initialize', 'signal', 'clear', 'finalize', 'wait']) {
    check(Number.isSafeInteger(code[name]?.offset) && code[name].offset > 0,
      'sdk_offsets.event_' + name + ' is null/absent in offsets/civ7-100.json — M0 must locate the Civ 7 nn::os event wrapper (offsets/README.md)');
    const region = await s.rpc.query(live.sdk + code[name].offset);
    check(!region.result && region.permissions === 5, 'Event entry is not executable: ' + name);
  }
  await s.record({operation: 'eventCodeVerified', backend: config.workerBackend()});
}

function address(s, pointer) {
  check(pointer % 8 === 0 && pointer >= s.base && pointer + 8 <= s.base + s.bytes,
    'Event is outside the owned allocation');
}

async function initialize(s, pointer) {
  address(s, pointer);
  await s.rpc.call3(live.sdk + code.initialize.offset, pointer, 0, 0);
  // barbarism: the unsignaled/manual-reset state check doubles as the Civ 7
  // nn::os EventType layout probe — if the state bytes move, this fails loudly
  // and M0 documents the new layout instead of the wave corrupting a gate.
  const bytes = await s.read(pointer, 8);
  check(bytes[0] === 0 && bytes[1] === 1 && bytes.readUInt32LE(4) === 0,
    'Manual-reset event did not initialize unsignaled');
}

async function signal(s, pointer) {
  address(s, pointer);
  await s.rpc.call3(live.sdk + code.signal.offset, pointer, 0, 0);
}

async function clear(s, pointer) {
  address(s, pointer);
  await s.rpc.call3(live.sdk + code.clear.offset, pointer, 0, 0);
}

async function finalize(s, pointer) {
  address(s, pointer);
  check(!s.threads.size, 'Cannot finalize events while workers remain');
  await s.rpc.call3(live.sdk + code.finalize.offset, pointer, 0, 0);
}

module.exports = {verify, initialize, signal, clear, finalize, code};
