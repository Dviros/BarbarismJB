// engine/switch2/app/worker.cjs — verify the worker entry points for the
// configured backend before any wave runs.
//
// barbarism: Verify the worker entry points for the configured backend.
// - frames backend: original ns2jb behavior — the four SmileBASIC SDK worker
//   gadgets (loadTable/call4/saveResult64/exit) plus pthread/longjmp entries,
//   pinned by instruction bytes from app/thread-code.json (which must be
//   re-fingerprinted for Civ 7 before this backend can be used).
// - ropchain backend: the pthread/longjmp/sleep entries resolve from
//   offsets/civ7-100.json (absolute addresses on `live`); there are no
//   instruction pins yet, so presence + address sanity is the check (the M0
//   region hashes in the offsets table are the pin — see lib/offsets.cjs).
// - rawsvc backend: the ropchain checks PLUS the raw svcCreateThread-family
//   entries (svc.create_thread/start_thread/exit_thread/wait_synchronization/
//   get_thread_priority/get_thread_core_mask) — the civswitch-kit
//   hardware-qualified path for Civ 7 1.0.0, where pthread_create silently
//   no-ops (docs/CIVSWITCH-INTEGRATION.md §2c).
const {check, live} = require('./session.cjs');
const framesCode = require('./thread-code.json').functions;
const {SENTINEL} = require('../../shared/frames.cjs');
const config = require('../../shared/config.cjs');

const backend = config.workerBackend();

// barbarism: thread-code `offset` fields are sdk-relative, so both backends can
// be consumed uniformly as live.sdk + code[name].offset.
const ropchainCode = (() => {
  const sdkRelative = absolute => Number.isSafeInteger(absolute) && absolute > 0 ? absolute - live.sdk : null;
  const code = {
    create: {offset: sdkRelative(live.sdkFn?.pthread_create)},
    join: {offset: sdkRelative(live.sdkFn?.pthread_join)},
    longjmp: {offset: sdkRelative(live.sdkFn?.longjmp)},
    exit: {offset: sdkRelative(live.sdkFn?.pthread_exit)},
    sleep: {offset: live.svc?.sleep_thread ? live.svc.sleep_thread - live.sdk : null},
    tryWait: {offset: null} // no known Civ 7 tryjoin; join() blocks (180s bridge stop)
  };
  return code;
})();

const code = backend === 'frames' ? framesCode : ropchainCode;

// barbarism: raw-svc entries (civswitch-kit thread-code.json rawSvc.functions,
// hardware-qualified on Civ 7 1.0.0) for the 'rawsvc' backend — resolved from
// the same offsets table as absolute live.svc addresses.
const rawSvcCode = {
  createRaw: {offset: live.svc?.create_thread ? live.svc.create_thread - live.sdk : null},
  startRaw: {offset: live.svc?.start_thread ? live.svc.start_thread - live.sdk : null},
  exitRaw: {offset: live.svc?.exit_thread ? live.svc.exit_thread - live.sdk : null},
  waitRaw: {offset: live.svc?.wait_synchronization ? live.svc.wait_synchronization - live.sdk : null},
  getPriority: {offset: live.svc?.get_thread_priority ? live.svc.get_thread_priority - live.sdk : null},
  getCoreMask: {offset: live.svc?.get_thread_core_mask ? live.svc.get_thread_core_mask - live.sdk : null}
};
const RAW_KEYS = {createRaw: 'create_thread', startRaw: 'start_thread', exitRaw: 'exit_thread',
  waitRaw: 'wait_synchronization', getPriority: 'get_thread_priority', getCoreMask: 'get_thread_core_mask'};

async function verifyWorkerCode(session) {
  if (backend === 'frames') {
    for (const name of ['create', 'join', 'current', 'longjmp', 'loadTable',
      'call4', 'saveResult64', 'exit', 'tryWait', 'tryWaitImplementation', 'sleep']) {
      check(code[name], 'Missing worker signature: ' + name);
      await session.verifyCode(code[name], name);
    }
  } else {
    for (const name of ['create', 'join', 'longjmp', 'exit', 'sleep']) {
      const key = name === 'create' ? 'pthread_create' : name === 'join' ? 'pthread_join' :
        name === 'exit' ? 'pthread_exit' : name === 'sleep' ? 'svc.sleep_thread' : name;
      check(code[name]?.offset > 0,
        'ropchain worker backend needs ' + (name === 'sleep' ? 'svc.sleep_thread' : 'sdk_offsets.' + key) +
        ' in offsets/civ7-100.json (missing or null)');
      const region = await session.rpc.query(live.sdk + code[name].offset);
      check(!region.result && region.permissions === 5, 'Worker entry is not executable: ' + name);
    }
    if (backend === 'rawsvc') {
      for (const name of Object.keys(RAW_KEYS)) {
        check(rawSvcCode[name]?.offset > 0,
          'rawsvc worker backend needs svc.' + RAW_KEYS[name] +
          ' in offsets/civ7-100.json (missing or null — run engine/carrier/civ7js/import-civswitch-offsets.cjs)');
        const region = await session.rpc.query(live.sdk + rawSvcCode[name].offset);
        check(!region.result && region.permissions === 5, 'Raw worker entry is not executable: ' + name);
      }
    }
    check(['ropchain', 'rawsvc'].includes(config.workerBackend()), 'Unknown worker backend');
  }
  await session.record({operation: 'workerCodeVerified', backend});
}
module.exports = {verifyWorkerCode, code, rawSvcCode, SENTINEL, backend};
