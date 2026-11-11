// Set only owned parked workers to a CPU allowed for this process.
// barbarism: PORTED to the offsets table (was: the SmileBASIC six-wrapper pin
// table thread-scheduling-reference.json plus the nnCompatThin GOT walk in
// compat-affinity-reference.json, behind a loud unported() guard). Four
// sdk_offsets entries now carry the wrappers (see offsets/README.md):
//   sdk_offsets.set_affinity         pthread_setaffinity_np (schema slot)
//   sdk_offsets.get_affinity         pthread_getaffinity_np
//   sdk_offsets.available_core_mask  nn::os::GetThreadAvailableCoreMask()
//   sdk_offsets.current_core_number  nn::os::GetCurrentCoreNumber()
// The wave's per-role core pinning keeps its validation shape exactly: one-bit
// masks within the allowed set, set + read-back verification per worker
// (probe-reserved-gap.cjs pinAll). The SmileBASIC compatibility-module cross
// check (a GOT-resolved nnCompatThin wrapper that masked the available set to
// three bits) has no known Civ 7 counterpart — one available-mask source is
// used and recorded; M0 RE notes whether Civ 7's sdk reports a restricted set.
const {live, check, u64} = require("./session.cjs");
const nativeOffsets = require('./native-offsets.cjs');

// barbarism: name -> offsets key; code keeps the upstream sdk-relative
// {offset} shape. Null until the table carries the key; verify() names it.
const WRAPPERS = {get: 'get_affinity', set: 'set_affinity',
  available: 'available_core_mask', current: 'current_core_number'};
const code = Object.fromEntries(Object.entries(WRAPPERS).map(([name, key]) =>
  [name, {offset: nativeOffsets.optionalSdkOffset(live, key)}]));

function requireWrapper(name) {
  check(Number.isSafeInteger(code[name]?.offset) && code[name].offset > 0,
    'sdk_offsets.' + WRAPPERS[name] + ' is null/absent in offsets/civ7-100.json — M0 must locate the Civ 7 affinity wrapper (offsets/README.md)');
  return code[name].offset;
}

async function verify(s) {
  if (s.affinityCodeVerified) return;
  for (const name of Object.keys(WRAPPERS)) {
    const offset = requireWrapper(name);
    const region = await s.rpc.query(live.sdk + offset);
    check(!region.result && region.permissions === 5, 'Affinity entry is not executable: ' + name);
  }
  s.affinityCodeVerified = true;
}

async function available(s) {
  await verify(s);
  if (!s.affinityMasks) {
    // barbarism: one available-mask source (the SDK wrapper); the SmileBASIC
    // build cross-checked a second, compat-module-masked value — Civ 7's
    // equivalent, if any, is an M0 RE question recorded here when answered.
    const mask = await s.rpc.call3(live.sdk + requireWrapper('available'), 0, 0, 0);
    check(Number.isSafeInteger(mask) && mask > 0 && mask < 2 ** 32, 'Unexpected available CPU mask');
    s.affinityMasks = {availableMask: String(mask)};
    await s.record({operation: 'availableCoreMasks', ...s.affinityMasks});
  }
  return BigInt(s.affinityMasks.availableMask);
}

function currentCoreCall() {
  const offset = requireWrapper('current');
  return {kind: 'core', function: live.sdk + offset, args: [0, 0, 0, 0]};
}

async function get(s, worker) {
  check(s.threads.has(worker.thread), 'Affinity query requires an owned worker');
  await verify(s);
  const output = s.base + 0x2800;
  await s.write(output, Buffer.alloc(8));
  check(!await s.rpc.call3(live.sdk + requireWrapper('get'),
    worker.thread, 8, output), 'Worker affinity query failed');
  const mask = (await s.readOwned(output, 8)).readBigUInt64LE();
  check(mask > 0n, 'Worker has no allowed CPU cores');
  return mask;
}

async function pin(s, worker, mask) {
  const before = await get(s, worker);
  const allowed = await available(s);
  check(mask > 0n && (mask & (mask - 1n)) === 0n && (mask & allowed) === mask,
    'Choose one CPU allowed for this process');
  const input = s.base + 0x2800;
  await s.write(input, u64(mask));
  const result = await s.rpc.call3(live.sdk + requireWrapper('set'), worker.thread, 8, input);
  await s.record({operation: 'workerAffinitySet', label: worker.label, thread: worker.thread,
    before: before.toString(), requested: mask.toString(), result});
  check(!result, 'Worker affinity update failed: ' + result);
  check(await get(s, worker) === mask, 'Worker affinity readback differs');
  await s.record({operation: 'workerAffinity', label: worker.label, thread: worker.thread,
    before: before.toString(), after: mask.toString()});
  return {before: before.toString(), after: mask.toString()};
}

async function pinAll(s, workers, masks) {
  check(workers.length === masks.length && workers.length <= 32, 'Invalid worker affinity list');
  for (let i = 0; i < workers.length; i++) await pin(s, workers[i], masks[i]);
}

module.exports = {verify, available, currentCoreCall, get, pin, pinAll};
