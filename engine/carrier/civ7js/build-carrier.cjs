// engine/carrier/civ7js/build-carrier.cjs — bake offsets/civ7-100.json into
// payloads/civshim.js, producing the single self-contained carrier file that
// gets pushed through the CivSwitch :9026 loader.
//
// This is BarbarismJB's answer to the kit's set-pc-ip.ps1 + civ_bridge.js
// CONFIG block (kit:README.md §5): instead of hand-editing the console-side
// script before each deployment, the host bakes the offsets table into the
// shim so the console boots with QUERY/SLEEP/THREAD (and now the raw-svc
// ops 12-15) live from the first frame — no op-11 upload round-trip needed.
// Values the table does not know stay null and the shim degrades exactly as
// documented; the host still cross-checks and uploads via op 11 on connect.
//
// The bake is anchored on exact source strings; if payloads/civshim.js drifts
// (renamed CONFIG keys, changed quotes) this fails loudly instead of shipping
// a silently un-baked carrier.
//
// Origin: original — BarbarismJB. Offset VALUES come from the M0 dump or from
// the GPL-2.0 civswitch-kit via import-civswitch-offsets.cjs (provenance
// travels in the offsets file's _civswitch notes and the carrier banner).
// Docs: docs/CIVSWITCH-INTEGRATION.md §5.
'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const SHIM_RELATIVE = path.join('payloads', 'civshim.js');

// The exact null dict civshim.js ships with (14-space indent inside CONFIG).
// Any drift in the source must be reconciled here — never silently skipped.
const OFFSETS_ANCHOR = `        OFFSETS: {
            svc: {
                query_memory: null,             // svc #0x06 wrapper
                connect_to_named_service: null, // svc #0x1F wrapper
                send_sync_request: null,        // svc #0x21 wrapper
                sleep_thread: null,             // svc #0x0B wrapper
                close_handle: null,             // svc #0x16 wrapper
                wait_synchronization: null,     // svc #0x18 wrapper
                create_thread: null,            // svc #0x08 wrapper (raw threads)
                start_thread: null,             // svc #0x09 wrapper
                get_thread_priority: null,      // svc #0x0C wrapper
                get_thread_core_mask: null      // svc #0x0E wrapper
            },
            sdk_offsets: {
                longjmp: null,
                pthread_create: null,
                pthread_join: null,
                pthread_exit: null,
                thread_manager_global: null     // nn::os thread-manager global (op 15)
            },`;
const PORT_ANCHOR_RE = /^(\s*PORT:\s*)(\d+)(,\s*)$/m;

function renderOffsets(offsetsTable, shimPort) {
  const svc = offsetsTable?.svc || {};
  const sdk = offsetsTable?.sdk_offsets || {};
  const leaf = (key, value, comment) => {
    const text = Number.isSafeInteger(value) && value >= 0 ? String(value) : 'null';
    const pad = ' '.repeat(Math.max(1, 26 - key.length));
    return key + ':' + pad + text + ', // ' + comment;
  };
  return `        OFFSETS: {
            svc: {
                ${leaf('query_memory', svc.query_memory, 'svc #0x06 wrapper')}
                ${leaf('connect_to_named_service', svc.connect_to_named_service, 'svc #0x1F wrapper')}
                ${leaf('send_sync_request', svc.send_sync_request, 'svc #0x21 wrapper')}
                ${leaf('sleep_thread', svc.sleep_thread, 'svc #0x0B wrapper')}
                ${leaf('close_handle', svc.close_handle, 'svc #0x16 wrapper')}
                ${leaf('wait_synchronization', svc.wait_synchronization, 'svc #0x18 wrapper')}
                ${leaf('create_thread', svc.create_thread, 'svc #0x08 wrapper (raw threads)')}
                ${leaf('start_thread', svc.start_thread, 'svc #0x09 wrapper')}
                ${leaf('get_thread_priority', svc.get_thread_priority, 'svc #0x0C wrapper')}
                ${leaf('get_thread_core_mask', svc.get_thread_core_mask, 'svc #0x0E wrapper')}
            },
            sdk_offsets: {
                ${leaf('longjmp', sdk.longjmp, 'forged jmp_buf entry (op 8 / op 12)')}
                ${leaf('pthread_create', sdk.pthread_create, 'op 8 only — known silent no-op on Civ 7 1.0.0')}
                ${leaf('pthread_join', sdk.pthread_join, 'op 9 only')}
                ${leaf('pthread_exit', sdk.pthread_exit, 'ropchain tail (non-rawsvc chains)')}
                ${leaf('thread_manager_global', sdk.thread_manager_global, 'nn::os thread-manager global (op 15)')}
            },`;
}

// Build the carrier text. Returns {carrier, digest, filled:{svc,sdk}, port}.
// `offsetsTable` is the parsed offsets/civ7-100.json (or the degraded empty
// table run.cjs uses pre-M0 — the bake then just re-affirms the nulls).
function buildCarrier({shimSource, offsetsTable, shimPort}) {
  if (!shimSource.includes(OFFSETS_ANCHOR))
    throw Object.assign(Error('payloads/civshim.js no longer contains the expected null OFFSETS dict — ' +
      'update the OFFSETS_ANCHOR in engine/carrier/civ7js/build-carrier.cjs to match the new source'), {code: 'E_CARRIER_ANCHOR'});
  let carrier = shimSource.replace(OFFSETS_ANCHOR, renderOffsets(offsetsTable, shimPort));
  const portMatch = carrier.match(PORT_ANCHOR_RE);
  if (!portMatch)
    throw Object.assign(Error('payloads/civshim.js no longer contains the CONFIG PORT line — ' +
      'update PORT_ANCHOR_RE in engine/carrier/civ7js/build-carrier.cjs'), {code: 'E_CARRIER_ANCHOR'});
  if (Number.isInteger(shimPort) && shimPort >= 1024 && shimPort <= 65535) {
    carrier = carrier.replace(PORT_ANCHOR_RE, '$1' + shimPort + '$3');
    portMatch[2] = String(shimPort); // report the port actually baked
  }
  // Count only the slots the shim actually consumes (10 svc + 5 sdk_offsets).
  const live = pick => Object.values(pick).filter(value => Number.isSafeInteger(value) && value >= 0 && value !== null).length;
  const svcSlots = {query_memory: offsetsTable?.svc?.query_memory,
    connect_to_named_service: offsetsTable?.svc?.connect_to_named_service,
    send_sync_request: offsetsTable?.svc?.send_sync_request, sleep_thread: offsetsTable?.svc?.sleep_thread,
    close_handle: offsetsTable?.svc?.close_handle, wait_synchronization: offsetsTable?.svc?.wait_synchronization,
    create_thread: offsetsTable?.svc?.create_thread, start_thread: offsetsTable?.svc?.start_thread,
    get_thread_priority: offsetsTable?.svc?.get_thread_priority, get_thread_core_mask: offsetsTable?.svc?.get_thread_core_mask};
  const sdkSlots = {longjmp: offsetsTable?.sdk_offsets?.longjmp,
    pthread_create: offsetsTable?.sdk_offsets?.pthread_create, pthread_join: offsetsTable?.sdk_offsets?.pthread_join,
    pthread_exit: offsetsTable?.sdk_offsets?.pthread_exit,
    thread_manager_global: offsetsTable?.sdk_offsets?.thread_manager_global};
  const filled = {svc: live(svcSlots), sdk_offsets: live(sdkSlots)};
  const banner = '// barbarism-carrier: baked ' + new Date().toISOString() +
    ' | svc ' + filled.svc + '/10 live | sdk_offsets ' + filled.sdk_offsets + '/5 live' +
    ' | port ' + (portMatch[2] || '?') +
    ' | offsets sha256 ' + crypto.createHash('sha256')
      .update(JSON.stringify({svc: offsetsTable?.svc, sdk_offsets: offsetsTable?.sdk_offsets,
        modules: offsetsTable?.modules})).digest('hex').slice(0, 16) + '\n';
  // The shim is an async IIFE evaluated in the loader closure — a leading
  // comment is the only safe injection point.
  carrier = banner + carrier;
  return {
    carrier,
    digest: crypto.createHash('sha256').update(carrier).digest('hex'),
    filled,
    port: Number(portMatch[2])
  };
}

// API + CLI. CLI: node build-carrier.cjs [--out FILE] [--port N] [project-root]
async function main(argv = process.argv.slice(2)) {
  const args = [...argv];
  let out = null, port;
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--out') out = args[++i];
    else if (args[i] === '--port') port = Number(args[++i]);
    else positional.push(args[i]);
  }
  const project = path.resolve(positional[0] || process.cwd());
  let offsetsTable = {svc: {}, sdk_offsets: {}};
  try {
    offsetsTable = JSON.parse(await fs.readFile(path.join(project, 'offsets', 'civ7-100.json'), 'utf8'));
  } catch {
    console.error('note: no offsets/civ7-100.json — baking the null dict (degraded carrier, host op-11 upload still works)');
  }
  const shimSource = await fs.readFile(path.join(project, SHIM_RELATIVE), 'utf8');
  const built = buildCarrier({shimSource, offsetsTable, shimPort: port});
  if (out) {
    await fs.writeFile(out, built.carrier, {mode: 0o600});
    console.log('carrier written: ' + out + ' (' + built.carrier.length + ' bytes, sha256 ' + built.digest.slice(0, 16) + ')');
  } else {
    process.stdout.write(built.carrier);
  }
  console.error('baked svc entries: ' + built.filled.svc + ', sdk_offsets entries: ' + built.filled.sdk_offsets);
}

module.exports = {buildCarrier, OFFSETS_ANCHOR, SHIM_RELATIVE};

if (require.main === module) main().catch(error => {console.error(String(error.message || error)); process.exit(1);});
