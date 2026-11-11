// engine/shared/config.cjs — host-adaptation knobs shared by the app worker
// backend, the gap probe, and the RO donor files.
//
// Purpose: validate the BarbarismJB run configuration (env knobs) once, at
// the edge, with actionable E_CONFIG failures; expose the unported() guard.
// Docs: README.md "Engine adaptation points" + "Pending Civ 7 ports".
// Origin: original — BarbarismJB (new for the Civ 7 port; the ns2jb engine
// had no such knob layer).
//
// Knobs (values reach the spawned pipeline stages through the environment,
// set by run.cjs / BARBARISM_* flags):
//   BARBARISM_WORKER  'ropchain' (default; Civ 7 ROP-chain workers from
//                   offsets.gadgets + forged jmp_buf) or 'frames' (the legacy
//                   ns2jb SmileBASIC 4-gadget worker frames — only usable once
//                   Civ 7 equivalents of loadTable/call4/saveResult64/exit are
//                   fingerprinted into app/thread-code.json) or 'rawsvc'
//                   (ropchain chains launched through the civswitch-kit
//                   hardware-qualified raw svcCreateThread path: pthread_create
//                   silently no-ops on Civ 7 1.0.0, so this is the backend the
//                   wave should use on hardware — civshim ops 12-15).
//   BARBARISM_DONOR   'save' (default; donor = clone of the game's save: mount,
//                   /main + /main.npdm written at the save root — never inside
//                   save:/saves/ where XSTRIG.Civ7Save lives) or 'tmp' (the
//                   ns2jb donor choice).
//   BARBARISM_OWN_STORAGE_CMD  fsp-srv command that opens the process's own
//                   content storage for the reserved-gap probe (default 200;
//                   'measure-lively' is not a command — the probe always
//                   re-measures storageSize at runtime instead of assuming the
//                   SmileBASIC value).
const {fail} = require('./errors.cjs');

function pick(name, allowed, fallback) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;
  if (!allowed.includes(value))
    throw fail('E_CONFIG', name + ' must be one of ' + allowed.join('|') + ', got ' + JSON.stringify(value));
  return value;
}

// barbarism: loud failure for subsystems still pinned to the SmileBASIC SDK
// tables (sdk-functions/sdk-layout/event-code/timing-code/hash-code/
// thread-scheduling-reference json). These need Civ 7 offsets from the M0 dump
// before the corresponding pipeline stage can run (the M3/M4 port list in
// README.md). Called at entry so the failure is actionable instead of an
// instruction-mismatch error deep inside a stage.
function unported(what) {
  throw fail('E_UNPORTED', 'BarbarismJB: ' + what + ' is not ported to the Civ 7 process yet — it still ' +
    'needs SmileBASIC SDK pins replaced with offsets from the M0 dump ' +
    '(see README.md, "Pending Civ 7 ports"). This is M3+ work.');
}

module.exports = {
  workerBackend: () => pick('BARBARISM_WORKER', ['ropchain', 'frames', 'rawsvc'], 'ropchain'),
  donorMountSource: () => pick('BARBARISM_DONOR', ['save', 'tmp'], 'save'),
  ownStorageCommand: () => Number(pick('BARBARISM_OWN_STORAGE_CMD', ['200'], 200)),
  unported,
};
