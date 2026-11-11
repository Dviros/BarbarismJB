// engine/lib/offsets.cjs — loader for offsets/civ7-100.json, the contract
// between the M0 bootstrap tooling (svc scan / gadget scan / dump analysis)
// and the engine.
//
// Purpose: pin everything host-specific about the Civ 7 1.0.0 process in one
// file; fail loudly (E_OFFSETS) when a required entry is null/absent and
// warn when an optional pin is missing. Docs: DESIGN.md section 7,
// README.md "Offsets contract", offsets/README.md (M0 workflow).
// Origin: original — BarbarismJB (new for the Civ 7 port; ns2jb hardcoded
// the SmileBASIC SDK tables instead).
//
// Value convention (matching DESIGN.md section 7):
//   svc.*            offsets relative to the sdk module base (svc wrappers)
//   sdk_offsets.*    offsets relative to the sdk module base
//   gadgets.*        offsets relative to the main module base (38 MB NSO)
//   modules.*.base   informational only — the live bases come from the CIV1
//                    hello (ASLR); first_page_sha256 pins are the real check.
//   jmp_buf.layout   "x19@0/x20@8/.../x29@104/x30@112/sp@120/pc@128" —
//                    name@byteOffset inside the jmp_buf.
const fs = require('node:fs');
const path = require('node:path');
const {fail} = require('../shared/errors.cjs');

const OFFSETS_RELATIVE = path.join('offsets', 'civ7-100.json');

// Without these the engine cannot drive IPC or clean up handles at all.
const REQUIRED = ['svc.query_memory', 'svc.connect_to_named_service', 'svc.send_sync_request',
  'svc.sleep_thread', 'svc.close_handle'];
// The wave worker backend (ropchain) needs these; checked again at use time by
// shared/frames.cjs buildRopChain and app/native-worker.cjs.
const REQUIRED_WORKER = ['sdk_offsets.longjmp', 'sdk_offsets.pthread_create',
  'sdk_offsets.pthread_join', 'sdk_offsets.pthread_exit', 'sdk_offsets.memcpy'];
// Nice-to-have; absence logs a warning and the feature degrades.
const OPTIONAL = ['svc.cancel_synchronization', 'svc.wait_synchronization',
  'svc.get_system_tick', 'svc.query_process_memory', 'svc.get_thread_id', 'svc.get_process_id',
  'sdk_offsets.memset', 'sdk_offsets.set_affinity', 'jmp_buf.layout', 'jmp_buf.mangled'];

function entry(table, name) {
  const [group, key] = name.split('.');
  const value = table?.[group]?.[key];
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null;
}

function missing(table, names) {
  return names.filter(name => entry(table, name) === null);
}

// Load and validate offsets/civ7-100.json under `projectRoot` (defaults to the
// BarbarismJB checkout that contains engine/). Throws with an actionable
// message on every failure; never returns a half-trusted table.
function load(projectRoot = path.resolve(__dirname, '..', '..')) {
  const file = path.resolve(projectRoot, OFFSETS_RELATIVE);
  if (!fs.existsSync(file))
    throw fail('E_OFFSETS',
    'Missing ' + file + '.\n' +
      'Run the M0 bootstrap (payloads/dumper.js + tools/svc_scan.py + tools/gadget_scan.py, DESIGN.md section 3)\n' +
      'and write offsets/civ7-100.json — see offsets/civ7-100.template.json for the schema.');
  let table;
  try {table = JSON.parse(fs.readFileSync(file, 'utf8'));}
  catch (error) {throw fail('E_OFFSETS', 'offsets/civ7-100.json is not valid JSON: ' + error.message);}
  for (const group of ['target', 'modules', 'svc', 'sdk_offsets', 'jmp_buf', 'gadgets', 'pins'])
    if (!table[group] || typeof table[group] !== 'object')
      throw fail('E_OFFSETS', 'offsets/civ7-100.json is missing the "' + group + '" section (schema: offsets/civ7-100.template.json)');
  const absent = missing(table, REQUIRED);
  if (absent.length)
    throw fail('E_OFFSETS', 'offsets/civ7-100.json has null/absent REQUIRED entries: ' + absent.join(', ') + '.\n' +
      'These come from the M0 svc-site scan (DESIGN.md section 3). Refusing to run with a partial table.');
  const warnings = [];
  for (const name of [...missing(table, REQUIRED_WORKER), ...missing(table, OPTIONAL)])
    warnings.push('offsets warning: ' + name + ' is null/absent — the feature needing it will fail (or degrade) at use time');
  const version = table.target?.version, firmware = table.target?.firmware;
  if (version !== '1.0.0') warnings.push('offsets warning: target.version is ' + JSON.stringify(version) + ', expected "1.0.0" (Switch 1 cartridge)');
  if (firmware !== '23.0.1') warnings.push('offsets warning: target.firmware is ' + JSON.stringify(firmware) + ' — this chain is only valid on 23.0.1 (23.5.0 patches the fs Path::Normalize bug)');
  return {table, file, warnings, workerReady: missing(table, REQUIRED_WORKER).length === 0};
}

// Absolute runtime addresses for a live console session. `hello` is the
// addresses object from lib/connection.cjs (parseHello result). Every returned
// value is a plain Number — Switch 2 userland addresses fit in 39 bits, well
// below Number.MAX_SAFE_INTEGER — because the app-layer rpc client
// (switch2/app/rpc.cjs) and connection.json consumers require Number
// addresses and JSON.stringify cannot serialize BigInt.
function resolve(table, hello) {
  const sdk = Number(hello.sdk), main = Number(hello.main);
  if (!Number.isSafeInteger(sdk) || !Number.isSafeInteger(main))
    throw fail('E_OFFSETS', 'CIV1 hello carries a non-precise module base');
  const abs = (base, value) => {
    const sum = base + Number(value);
    if (!Number.isSafeInteger(sum)) throw fail('E_OFFSETS', 'Resolved address overflows safe integers');
    return sum;
  };
  const resolved = {
    sdk, main,
    svc: {}, sdkFn: {}, gadgets: {}
  };
  // Null-tolerant: entries the table does not carry resolve to 0 (falsy), so
  // transport checks can run against a pre-M0 console. load() is the strict
  // gate for pipeline runs; resolve() only maps what exists.
  for (const name of ['query_memory', 'connect_to_named_service', 'send_sync_request',
      'sleep_thread', 'close_handle'])
    resolved.svc[name] = table.svc[name] ? abs(sdk, table.svc[name]) : 0;
  for (const [name, value] of Object.entries(table.sdk_offsets || {}))
    if (typeof value === 'number' && value > 0) resolved.sdkFn[name] = abs(sdk, value);
  for (const [name, value] of Object.entries(table.gadgets || {}))
    if (typeof value === 'number' && value > 0) resolved.gadgets[name] = abs(main, value);
  // Cross-check the four svc wrappers the CIV1 hello carries directly.
  const carried = {query_memory: hello.svc?.query_memory,
    send_sync_request: hello.svc?.send_sync_request,
    connect_to_named_service: hello.svc?.connect_to_named_service,
    sleep_thread: hello.svc?.sleep_thread};
  for (const [name, value] of Object.entries(carried))
    if (value && value !== resolved.svc[name])
      throw fail('E_OFFSETS', 'CIV1 hello and offsets/civ7-100.json disagree on svc.' + name +
        ' (hello 0x' + value.toString(16) + ' vs table 0x' + resolved.svc[name].toString(16) + ')');
  return resolved;
}

// jmp_buf layout parser: "x19@0/x20@8/.../sp@120/pc@128" -> {x19:0, ..., sp:120, pc:128}.
function parseJmpBuf(jmpBuf) {
  const spec = jmpBuf?.layout;
  if (typeof spec !== 'string' || !spec.trim())
    throw fail('E_OFFSETS', 'offsets/civ7-100.json jmp_buf.layout is missing; the ropchain worker backend cannot forge a jmp_buf');
  if (jmpBuf.mangled === true)
    throw fail('E_OFFSETS', 'Civ 7 longjmp mangles pc/sp (pointer guard): guard support TODO (DESIGN.md section 9.1)');
  if (jmpBuf.mangled === null || jmpBuf.mangled === undefined)
    throw fail('E_OFFSETS', 'offsets/civ7-100.json jmp_buf.mangled is null; M0 RE must determine mangling before THREAD_CREATE is safe');
  const fields = {};
  for (const part of spec.split('/')) {
    const match = /^([a-z0-9]+)@([0-9]+)$/.exec(part.trim());
    if (!match || (match[1].startsWith('x') && !(Number(match[1].slice(1)) >= 19 && Number(match[1].slice(1)) <= 30)))
      throw fail('E_OFFSETS', 'Bad jmp_buf.layout entry: ' + part);
    fields[match[1]] = Number(match[2]);
  }
  for (const name of ['sp', 'pc']) if (!(name in fields))
    throw fail('E_OFFSETS', 'jmp_buf.layout lacks the mandatory "' + name + '" field');
  const size = Number(jmpBuf.size) || Math.max(...Object.values(fields)) + 8;
  return {fields, size};
}

module.exports = {load, resolve, parseJmpBuf, entry, missing, REQUIRED, REQUIRED_WORKER, OPTIONAL};
