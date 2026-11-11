// The legacy SDK reads the native counter but reports the Switch 1 frequency.
// barbarism: PORTED and parameterized (was: SmileBASIC timing-code.json pins
// behind a loud unported() guard). Upstream's battle-tested discovery is kept
// verbatim in shape, with the SmileBASIC ground truth moved into offsets.json:
//   1. tick source  — the generic svc GetSystemTick wrapper
//      (svc.get_system_tick, svc 0x1E) replaces the SmileBASIC mrs cntpct
//      pin. The wave uses it for receive-order timing (probe tick() calls).
//   2. true frequency — the SmileBASIC SDK's wrapper returned a hardcoded
//      19.2 MHz (the Switch 1 value; the SDK lied about Switch 2 hardware),
//      so ns2jb probed a SECOND module for the truth: the nnCompatThin
//      mapping, uniquely identified by its r-x size (45,989,888 bytes), whose
//      getter at +0x13d6f0 returned the real 31.25 MHz. For Civ 7 the module
//      signature and getter live in the offsets.json `timing` group:
//        timing.frequency_module_size — unique r-x mapping size identifying
//          the frequency source module
//        timing.frequency_offset     — offset in that module of the getter
//        timing.frequency_bytes      — optional instruction pin of the
//          getter's opening bytes (skip-with-warning until M0 provides it)
//        timing.expected_frequency   — the value the getter must return
//          (Switch 2 hardware truth, 31250000, verified by the ns2jb run)
//      M0 RE task (documented in offsets/README.md): find which Civ 7 module
//      reports the true counter frequency (its own nnSdk wrapper may already
//      be truthful — the SDK lie was a SmileBASIC-build artifact), measure the
//      module's unique mapping size, and pin the getter.
//   3. SDK cross-check — timing.sdk_frequency (nn::os GetSystemTickFrequency
//      equivalent, optional) is recorded; it is cross-checked only when
//      timing.sdk_expected_frequency is also provided, because Civ 7's SDK
//      value is unknown before M0 (SmileBASIC reported 19200000).
const fs = require('node:fs/promises');
const path = require('node:path');
const {live, check} = require("./session.cjs");
const nativeOffsets = require('./native-offsets.cjs');

// barbarism: sdk-relative tick entry for the wave's call() helper shape
// (probe-reserved-gap.cjs: tick = name => call(timing.code.tick.offset, ...)).
const code = {tick: {offset: nativeOffsets.optionalSvcOffset(live, 'get_system_tick')}};

async function verify(s) {
  check(Number.isSafeInteger(code.tick.offset) && code.tick.offset > 0,
    'svc.get_system_tick is null/absent in offsets/civ7-100.json — the wave needs it as the Civ 7 tick source (offsets/README.md)');
  const tickRegion = await s.rpc.query(live.sdk + code.tick.offset);
  check(!tickRegion.result && tickRegion.permissions === 5, 'The tick entry is not executable');
  // barbarism: one live probe (recorded) — the u32 transport truncation makes
  // a monotonicity check unreliable across the ~137 s low-32 wrap, so like
  // upstream we do not validate the tick value itself, only the entry.
  const tickProbe = await s.rpc.call3(live.sdk + code.tick.offset, 0, 0, 0);
  const moduleSize = nativeOffsets.number(live, 'timing.frequency_module_size');
  const frequencyOffset = nativeOffsets.number(live, 'timing.frequency_offset');
  const expected = nativeOffsets.number(live, 'timing.expected_frequency');
  const pinBytes = nativeOffsets.optionalString(live, 'timing.frequency_bytes');
  const map = JSON.parse(await fs.readFile(path.join(__dirname, 'memory-map.json'), 'utf8'));
  check(map.session === live.session && map.complete, 'Fresh memory map is missing');
  const candidates = map.regions.filter(region => region.permissions === 5 && BigInt(region.size) === BigInt(moduleSize));
  check(candidates.length === 1, 'Native compatibility module is not uniquely identified');
  const base = Number(BigInt(candidates[0].address));
  const region = await s.rpc.query(base);
  check(!region.result && region.permissions === 5 && Number(BigInt(region.address)) === base &&
    BigInt(region.size) === BigInt(moduleSize), 'Native module mapping changed');
  const address = base + frequencyOffset;
  if (pinBytes) {
    check((await s.read(address, pinBytes.length / 2)).toString('hex') === pinBytes,
      'Native frequency instructions differ from the captured module');
    await s.rpc.verifyFunction(address, pinBytes);
  } else {
    // No Civ 7 instruction pin yet: verify the entry is executable code and
    // record that the pin is pending (the value check below still gates).
    console.warn('BarbarismJB: timing.frequency_bytes pin pending the Civ 7 dump (entry verified executable)');
    const entry = await s.rpc.query(address);
    check(!entry.result && entry.permissions === 5, 'The native frequency entry is not executable');
  }
  const frequency = await s.rpc.call3(address, 0, 0, 0);
  check(frequency === expected, 'Unexpected counter frequency: ' + frequency + ' (expected ' + expected + ')');
  const record = {operation: 'counterFrequency', nativeModule: base, address, frequency,
    expectedFrequency: expected, instructionBytes: pinBytes || undefined,
    tick: {probe: tickProbe}};
  const sdkFrequencyOffset = nativeOffsets.optionalNumber(live, 'timing.sdk_frequency');
  if (sdkFrequencyOffset !== null) {
    const sdkRegion = await s.rpc.query(live.sdk + sdkFrequencyOffset);
    check(!sdkRegion.result && sdkRegion.permissions === 5, 'The SDK frequency entry is not executable');
    const sdkFrequency = await s.rpc.call3(live.sdk + sdkFrequencyOffset, 0, 0, 0);
    const sdkExpected = nativeOffsets.optionalNumber(live, 'timing.sdk_expected_frequency');
    if (sdkExpected !== null)
      check(sdkFrequency === sdkExpected, 'Unexpected SDK counter frequency: ' + sdkFrequency +
        ' (expected ' + sdkExpected + ')');
    record.sdkFrequency = sdkFrequency;
  }
  await s.record(record);
  return frequency;
}

module.exports = {verify, code};
