// engine/carrier/civ7js/import-civswitch-offsets.cjs — seed
// offsets/civ7-100.json from the hardware-validated civswitch-kit tables.
//
// The kit (gitee.com/mza1010/civswitch-kit, GPL-2.0; slapah/CivSwitch fork
// @7d422e52 + 8 patches) validated every value below on Civ 7 Switch-1 cart
// 1.0.0 hardware. The game statically links its nnSdk, so sdk-module offsets
// are properties of the CARTRIDGE BUILD — firmware-independent — and carry to
// our 23.0.0 console as-is (docs/CIVSWITCH-INTEGRATION.md §2d). What the kit
// does NOT supply stays null with an explicit _todo note + fetch method, so
// M0 shrinks to verification (first-page sha256 pins, main.size, the few
// listed gaps) instead of discovery.
//
// Provenance: every imported leaf gets recorded under `_civswitch.imported`
// with its kit source file; the output banner names the kit. The IMPORTED
// DATA is GPL-2.0-licensed kit output (facts); this tool and the mapping are
// original BarbarismJB code (PROVENANCE.md).
//
// CLI:
//   node import-civswitch-offsets.cjs <kit-root> [--out FILE] [--check]
//     kit-root  a checkout of the civswitch-kit (expects port/sdk-functions.civ7.json,
//               port/civ7-app/*.json, port/sdk-layout.civ7.json,
//               port/engine/shared/target.civ7.json)
//     --out     output path (default: offsets/civ7-100.json in this repo)
//     --check   verify the mapping without writing anything
'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');

const PROJECT = path.resolve(__dirname, '..', '..', '..');
const TEMPLATE = path.join(PROJECT, 'offsets', 'civ7-100.template.json');

async function readJson(file) {
  return JSON.parse(await fs.readFile(file, 'utf8'));
}

// Map a kit checkout to our offsets schema. Pure: (kit) -> (table, report).
function importKit(kit) {
  const report = {filled: {}, todo: {}, imported: [], sources: []};
  const note = (key, text) => {(report.todo[key] ||= []).push(text);};

  const table = {
    target: {
      game: 'Civ7 Switch1 cart', version: '1.0.0', firmware: '23.0.0',
      '_notes': 'Fixed cartridge build. Offsets seeded from the civswitch-kit (GPL-2.0, hardware-validated '
        + 'on Civ7 1.0.0 + fw 23.0.1; game-module offsets are firmware-independent — see '
        + 'docs/CIVSWITCH-INTEGRATION.md §2d for the 23.0.0-vs-23.0.1 analysis).'
    },
    modules: {
      main: {base: null, size: null, first_page_sha256: ''},
      sdk: {base: null, size: null, first_page_sha256: ''}
    },
    svc: {}, sdk_offsets: {}, timing: {}, mounts: {}, jmp_buf: {}, gadgets: {}, pins: {}
  };

  const put = (group, key, value, source) => {
    if (value === null || value === undefined || value === false) return false;
    table[group][key] = value;
    report.filled[group + '.' + key] = value;
    report.imported.push(group + '.' + key + ' <- ' + source);
    return true;
  };

  // ---- port/sdk-functions.civ7.json (validated core entries) --------------
  const f = kit.functions;
  if (f) {
    put('svc', 'query_memory', f.svcQueryMemory?.offset, 'sdk-functions.civ7.json:svcQueryMemory');
    put('svc', 'send_sync_request', f.svcSendSyncRequest?.offset ?? f.send?.offset, 'sdk-functions.civ7.json');
    put('svc', 'close_handle', f.svcCloseHandle?.offset ?? f.close?.offset, 'sdk-functions.civ7.json');
    put('sdk_offsets', 'memcpy', f.memcpy?.offset, 'sdk-functions.civ7.json:memcpy');
    put('sdk_offsets', 'memset', f.memset?.offset, 'sdk-functions.civ7.json:memset');
    put('sdk_offsets', 'memmove', f.memmove?.offset, 'sdk-functions.civ7.json:memmove');
    report.sources.push('port/sdk-functions.civ7.json');
  }

  // ---- port/civ7-app/thread-code.json (pthread/raw-svc/event tables) ------
  const t = kit.threadCode;
  if (t) {
    put('sdk_offsets', 'longjmp', t.functions?.longjmp?.offset, 'thread-code.json:functions.longjmp');
    put('sdk_offsets', 'pthread_create', t.functions?.create?.offset, 'thread-code.json:functions.create');
    put('sdk_offsets', 'pthread_join', t.functions?.join?.offset, 'thread-code.json:functions.join');
    put('sdk_offsets', 'pthread_exit', t.functions?.exit?.offset, 'thread-code.json:functions.exit');
    put('svc', 'sleep_thread', t.functions?.sleep?.offset,
      'thread-code.json:functions.sleep (nn::os SleepThread thunk — svc #0x0B effect; raw wrapper stays an M0 svc_scan find)');
    const raw = t.rawSvc;
    if (raw) {
      put('svc', 'create_thread', raw.functions?.createThread?.offset, 'thread-code.json:rawSvc.functions.createThread');
      put('svc', 'start_thread', raw.functions?.startThread?.offset, 'thread-code.json:rawSvc.functions.startThread');
      put('svc', 'exit_thread', raw.functions?.exitThread?.offset,
        'thread-code.json:rawSvc.functions.exitThread (svc #0x0A — NEVER #0x07, that is svcExitProcess)');
      put('svc', 'wait_synchronization', raw.functions?.waitSynchronization?.offset, 'thread-code.json:rawSvc.functions.waitSynchronization');
      put('svc', 'get_thread_priority', raw.functions?.getThreadPriority?.offset, 'thread-code.json:rawSvc.functions.getThreadPriority');
      put('svc', 'get_thread_core_mask', raw.functions?.getThreadCoreMask?.offset, 'thread-code.json:rawSvc.functions.getThreadCoreMask');
      put('sdk_offsets', 'thread_manager_global', raw.managerList?.globalPointerOffset,
        'thread-code.json:rawSvc.managerList.globalPointerOffset (bias 0xF0, sentinel +0x1D0, handle@+0x1B0 baked into civshim op 15)');
    }
    report.sources.push('port/civ7-app/thread-code.json');
  }

  // ---- port/civ7-app/event-code.json ---------------------------------------
  const e = kit.eventCode;
  if (e?.functions) {
    put('sdk_offsets', 'event_initialize', e.functions.initialize?.offset, 'event-code.json');
    put('sdk_offsets', 'event_finalize', e.functions.finalize?.offset, 'event-code.json');
    put('sdk_offsets', 'event_signal', e.functions.signal?.offset, 'event-code.json');
    put('sdk_offsets', 'event_clear', e.functions.clear?.offset, 'event-code.json');
    put('sdk_offsets', 'event_wait', e.functions.wait?.offset, 'event-code.json');
    report.sources.push('port/civ7-app/event-code.json');
  }

  // ---- port/civ7-app/timing-code.json --------------------------------------
  const tc = kit.timingCode;
  if (tc?.functions) {
    put('timing', 'sdk_frequency', tc.functions.frequency?.offset, 'timing-code.json (the legacy 19.2 MHz constant)');
    table.timing.sdk_expected_frequency = 19200000;
    table.timing.expected_frequency = 31250000;
    report.imported.push('timing.sdk_expected_frequency <- kit OFFSETS-REPORT (legacy SDK constant 19.2 MHz)');
    report.sources.push('port/civ7-app/timing-code.json');
  }

  // ---- port/civ7-app/hash-code.json ----------------------------------------
  if (Number.isInteger(kit.hashCode?.offset))
    put('sdk_offsets', 'sha256', kit.hashCode.offset, 'hash-code.json (nnSdk SHA-256 wrapper)');

  // ---- port/civ7-app/thread-scheduling-reference.json ----------------------
  const s = kit.scheduling;
  if (s?.functions) {
    put('sdk_offsets', 'set_affinity', s.functions['pthread_setaffinity_np']?.offset,
      'thread-scheduling-reference.json:pthread_setaffinity_np (kit preferred: direct nn::os Set/GetThreadCoreMask '
      + s.functions['nn::os::SetThreadCoreMask(nn::os::ThreadType*, int, unsigned long)']?.offset + '/'
      + s.functions['nn::os::GetThreadCoreMask(int*, unsigned long*, nn::os::ThreadType const*)']?.offset + ')');
    put('sdk_offsets', 'get_affinity', s.functions['pthread_getaffinity_np']?.offset, 'thread-scheduling-reference.json');
    put('sdk_offsets', 'available_core_mask', s.functions['nn::os::GetThreadAvailableCoreMask()']?.offset, 'thread-scheduling-reference.json');
    put('sdk_offsets', 'current_core_number', s.functions['nn::os::GetCurrentCoreNumber()']?.offset, 'thread-scheduling-reference.json');
    report.sources.push('port/civ7-app/thread-scheduling-reference.json');
  }

  // ---- port/sdk-layout.civ7.json + sdk-proxy-code.json ---------------------
  if (Number.isInteger(kit.layout?.mountTableOffset))
    put('mounts', 'table_offset', kit.layout.mountTableOffset, 'sdk-layout.civ7.json:mountTableOffset');
  const proxy = kit.proxy;
  if (proxy) {
    if (Number.isInteger(proxy.globalOffset))
      put('mounts', 'proxy_global', proxy.globalOffset, 'sdk-proxy-code.json:globalOffset (getter ' + proxy.functionOffset + ')');
    report.sources.push('port/civ7-app/sdk-proxy-code.json');
  }

  // ---- port/engine/shared/target.civ7.json ---------------------------------
  const target = kit.target;
  if (target) {
    if (Number.isInteger(target.sdkBytes)) {
      table.modules.sdk.size = target.sdkBytes;
      report.imported.push('modules.sdk.size <- target.civ7.json:sdkBytes (sdk TEXT extent 0x602000)');
    }
    if (target.sessionManager) {
      put('mounts', 'manager_state_offset', target.sessionManager.stateOffset, 'target.civ7.json:sessionManager (their runtime probe confirmed 0x800/0x5C/3)');
      put('mounts', 'manager_state_value', target.sessionManager.stateValue, 'target.civ7.json:sessionManager');
      put('mounts', 'manager_magic_offset', 8, 'kit PORT-HANDOFF runtime probe (0x800 magic at offset 8)');
      put('mounts', 'manager_magic_value', 2048, 'kit PORT-HANDOFF runtime probe (0x800 magic)');
    }
    table._civswitchGeometry = {
      pinningAllocationBytes: target.pinningAllocationBytes ?? null,
      heapJitterBytes: target.heapJitterBytes ?? null,
      fieldCopies: target.fieldCopies ?? null,
      retainedCaptureBytes: target.retainedCaptureBytes ?? null,
      retainedCaptureOffset: target.retainedCaptureOffset ?? null,
      writeSize: 0x800000, probeReadSize: 0x10000, positiveFillSegment: 63,
      threadStackBytes: target.thread?.stackBytes ?? null, borrowedPriorityObserved: 43,
      waitTimeoutResult: 59905,
      sdkCrc32: target.hello?.sdkCrc32 ?? null,
      '_notes': 'Civ7-BC fs geometry measured by the kit on fw 23.0.1 (expected to carry to 23.0.0 — '
        + 'see docs/CIVSWITCH-INTEGRATION.md §2d). Consumed by the probe GEOMETRY knobs / runbook.'
    };
    report.sources.push('port/engine/shared/target.civ7.json');
  }

  // ---- jmp_buf decoded from the kit longjmp body ---------------------------
  if (Number.isInteger(t?.functions?.longjmp?.offset)) {
    table.jmp_buf = {
      size: 0x90,
      layout: 'x19-x30@0x00..0x50, sp@0x60, d8-d15@0x68..0x88 (decoded from thread-code.json functions.longjmp.bytes: '
        + 'ldp x19..x30 pairs; ldr x2,[x0,#0x60]; mov sp,x2; ldp d8..d15 pairs; br x30 — NO guard/PAC ops)',
      mangled: false,
      guard_tls_offset: null
    };
    report.imported.push('jmp_buf <- decoded from thread-code.json functions.longjmp (CONFIRM in Ghidra during M0 — the ropchain backend forges this layout)');
  }

  // ---- gadgets: raw-thread exit is the sdk svc #0x0A wrapper ---------------
  if (Number.isInteger(t?.rawSvc?.functions?.exitThread?.offset))
    table.gadgets.exit_thread = null; // main-relative in our schema; the rawsvc backend uses svc.exit_thread directly
  note('gadgets.exit_thread', 'the rawsvc backend exits chains at svc.exit_thread (sdk-relative, imported above); '
    + 'the main-relative gadget stays an M2 gadget_scan find for the frames/ropchain backends');

  // ---- the explicit TODO surface (M0 remainder) -----------------------------
  note('modules.*.first_page_sha256', 'M0 dumper phase B: sha256 of the first 0x1000 bytes of each region file — the pin run.cjs checks before anything native runs');
  note('modules.main.size', 'M0 dumper phase B manifest: sum of the contiguous main_* regions');
  note('svc.connect_to_named_service', 'not emitted by the kit (their engine uses nn::sm::GetServiceHandle sdk+0x14CC90 instead). '
    + 'Fetch: M0 svc_scan.py svc #0x1F, or re-point session open at GetServiceHandle (recorded: 0x14CC90)');
  note('timing.frequency_module_size', 'kit uses measured mode (validate the 19.2 MHz SDK value at sdk_frequency, then measure the real tick over 10 s, ±10%); '
    + 'if our timing.cjs keeps requiring the second module, find it in the M0 phase-B map (SmileBASIC reference: nnCompatThin 45989888 r-x)');
  note('timing.frequency_offset', 'same as frequency_module_size — or adopt the kit measured mode');
  note('mounts.accessor_*', 'kit sdk-layout carries only the table head + 4 verified functions; the accessor/service layout constants are the same nnSdk '
    + 'generation as SmileBASIC — confirm in Ghidra from our M0 dump (SmileBASIC reference values in the template notes)');
  note('gadgets.{pivot,ret,svc_tail,blr_after_ldp}', 'M0 gadget_scan on the main region file (args_loader/frame_ldp/indirect_call/load_x21/store_result are pre-pinned from core.js gadgets — re-verify)');

  // ---- keep the template shape: nulls for everything not imported ----------
  const template = kit.template;
  for (const group of ['svc', 'sdk_offsets', 'timing', 'mounts', 'gadgets']) {
    for (const key of Object.keys(template[group] || {})) {
      if (key.startsWith('_')) continue;
      if (!(key in table[group])) table[group][key] = template[group][key] ?? null;
    }
  }
  table.pins = {region_hashes: {}};
  table._civswitch = {
    source: 'gitee.com/mza1010/civswitch-kit (snapshot 2026-11-10, GPL-2.0) — slapah/CivSwitch fork @7d422e52 + 8 patches',
    importedCount: report.imported.length,
    imported: report.imported,
    firmware_note: 'game-module offsets are cartridge-build constants (fw-independent). fs-sysmodule geometry was '
      + 'measured on 23.0.1; 23.0.1 changed only sdb per community notes, so it is expected to carry to 23.0.0 — '
      + 'verified day-one by the first-page pins + the probe pin-cost row.',
    todo: report.todo
  };
  return {table, report};
}

async function loadKit(kitRoot) {
  const join = (...parts) => path.join(kitRoot, ...parts);
  const tryJson = async file => {try {return await readJson(file);} catch {return null;}};
  const kit = {
    functions: await tryJson(join('port', 'sdk-functions.civ7.json')),
    threadCode: await tryJson(join('port', 'civ7-app', 'thread-code.json')),
    eventCode: await tryJson(join('port', 'civ7-app', 'event-code.json')),
    timingCode: await tryJson(join('port', 'civ7-app', 'timing-code.json')),
    hashCode: await tryJson(join('port', 'civ7-app', 'hash-code.json')),
    scheduling: await tryJson(join('port', 'civ7-app', 'thread-scheduling-reference.json')),
    layout: await tryJson(join('port', 'sdk-layout.civ7.json')),
    proxy: await tryJson(join('port', 'civ7-app', 'sdk-proxy-code.json')),
    target: await tryJson(join('port', 'engine', 'shared', 'target.civ7.json')),
    template: await readJson(TEMPLATE)
  };
  const missing = Object.entries(kit).filter(([, value]) => value === null).map(([key]) => key);
  if (missing.includes('template')) throw Error('cannot read the offsets template at ' + TEMPLATE);
  const critical = ['functions', 'threadCode', 'target'];
  const absent = critical.filter(key => missing.includes(key));
  if (absent.length) throw Error('kit root ' + kitRoot + ' is missing: ' +
    absent.map(key => key).join(', ') + ' (expected a civswitch-kit checkout — git clone https://gitee.com/mza1010/civswitch-kit)');
  if (missing.length) reportOptional(missing);
  return kit;
}

let optionalNoted = false;
function reportOptional(missing) {
  if (optionalNoted) return;
  optionalNoted = true;
  console.error('note: kit tables not found (some offsets stay null): ' + missing.join(', '));
}

async function main(argv = process.argv.slice(2)) {
  const args = [...argv];
  let kitRoot = null, out = path.join(PROJECT, 'offsets', 'civ7-100.json'), check = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--out') out = path.resolve(args[++i]);
    else if (args[i] === '--check') check = true;
    else if (!kitRoot) kitRoot = path.resolve(args[i]);
  }
  if (!kitRoot) {
    console.error('usage: node import-civswitch-offsets.cjs <civswitch-kit-root> [--out offsets/civ7-100.json] [--check]');
    process.exit(2);
  }
  const kit = await loadKit(kitRoot);
  const {table, report} = importKit(kit);
  console.log('civswitch-kit import: ' + report.imported.length + ' values filled from ' + report.sources.length + ' kit tables');
  for (const line of report.imported) console.log('  ' + line);
  const todos = Object.keys(report.todo);
  console.log('M0 remainder (' + todos.length + ' keys stay null):');
  for (const key of todos) console.log('  ' + key + ' — ' + report.todo[key][0]);
  if (check) {console.log('--check: mapping verified, nothing written.'); return;}
  await fs.mkdir(path.dirname(out), {recursive: true});
  await fs.writeFile(out, JSON.stringify(table, null, 2) + '\n', {mode: 0o600});
  console.log('written: ' + out);
}

module.exports = {importKit, loadKit};

if (require.main === module) main().catch(error => {console.error(String(error.message || error)); process.exit(1);});
