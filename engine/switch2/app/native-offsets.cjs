// engine/switch2/app/native-offsets.cjs — offsets-table lookups for the
// app-layer modules ported off the SmileBASIC SDK pin tables.
//
// barbarism: original — BarbarismJB. lib/offsets.cjs validates the table at
// startup and resolves the REQUIRED svc wrappers plus every sdk_offsets/gadgets
// entry onto `live` (connection.json), but the Civ 7 port also consumes entries
// the loader does not resolve itself: extra svc wrappers
// (cancel_synchronization, get_system_tick) and the new `timing` / `mounts`
// groups. These helpers read them with the same fail-loud contract the loader
// uses for REQUIRED entries: every miss throws E_OFFSETS naming the exact
// offsets/civ7-100.json key, so an M0 dump lights the consuming module up
// without further code changes. Optional lookups return null so callers can
// degrade explicitly (and record that they did).
const {fail} = require('../../shared/errors.cjs');

const GUIDE = ' — fill it from the M0 dump (offsets/README.md; schema: offsets/civ7-100.template.json)';

function raw(live, name) {
  const [group, key] = String(name).split('.');
  const value = live?.offsets?.[group]?.[key];
  if (value === undefined || value === null)
    throw fail('E_OFFSETS', 'offsets/civ7-100.json ' + name + ' is null/absent' + GUIDE);
  return value;
}

// A positive safe-integer table entry (offset, size, expected value, ...).
function number(live, name) {
  const value = raw(live, name);
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0)
    throw fail('E_OFFSETS', 'offsets/civ7-100.json ' + name + ' is not a positive integer: ' + JSON.stringify(value) + GUIDE);
  return value;
}

function optionalNumber(live, name) {
  const value = live?.offsets?.[String(name).split('.')[0]]?.[String(name).split('.')[1]];
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null;
}

function optionalString(live, name) {
  const value = live?.offsets?.[String(name).split('.')[0]]?.[String(name).split('.')[1]];
  return typeof value === 'string' && value.length ? value : null;
}

// A non-empty list of short ASCII names (e.g. mounts.names).
function list(live, name) {
  const value = raw(live, name);
  if (!Array.isArray(value) || !value.length || !value.every(item =>
      typeof item === 'string' && /^[a-z0-9][a-z0-9:-]{0,15}$/.test(item)))
    throw fail('E_OFFSETS', 'offsets/civ7-100.json ' + name + ' is not a non-empty list of mount names' + GUIDE);
  return value;
}

// sdk-relative offset of an svc wrapper entry (svc.* are sdk-module-relative
// per the table convention; offsets.cjs only resolves five of them absolutely).
function svcOffset(live, name) {return number(live, 'svc.' + name);}
function optionalSvcOffset(live, name) {return optionalNumber(live, 'svc.' + name);}

// Absolute runtime address of an svc wrapper (prefers the loader-resolved
// live.svc entry when one exists, so the two paths can never disagree).
function svc(live, name) {
  const resolved = live?.svc?.[name];
  if (typeof resolved === 'number' && resolved > 0) return resolved;
  return live.sdk + svcOffset(live, name);
}
function optionalSvc(live, name) {
  const offset = optionalSvcOffset(live, name);
  return offset === null ? null : live.sdk + offset;
}

// Absolute runtime address of an sdk_offsets.* function (live.sdkFn carries
// every resolved entry; a miss means the table key is null/absent).
function sdkEntry(live, name) {
  const resolved = live?.sdkFn?.[name];
  if (!(typeof resolved === 'number' && Number.isSafeInteger(resolved) && resolved > 0))
    throw fail('E_OFFSETS', 'sdk_offsets.' + name + ' is null/absent in offsets/civ7-100.json' + GUIDE);
  return resolved;
}
function sdkOffset(live, name) {return sdkEntry(live, name) - live.sdk;}
function optionalSdk(live, name) {
  const resolved = live?.sdkFn?.[name];
  return typeof resolved === 'number' && resolved > 0 ? resolved : null;
}
function optionalSdkOffset(live, name) {
  const resolved = optionalSdk(live, name);
  return resolved === null ? null : resolved - live.sdk;
}

module.exports = {number, optionalNumber, optionalString, list,
  svcOffset, optionalSvcOffset, svc, optionalSvc,
  sdkEntry, sdkOffset, optionalSdk, optionalSdkOffset};
