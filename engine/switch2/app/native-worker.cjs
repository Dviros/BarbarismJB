// engine/switch2/app/native-worker.cjs — start/launch/join/restart/cancel
// native wave workers through the configured backend.
//
// barbarism: Worker backends. 'frames' is the original ns2jb variable-size
// SmileBASIC SDK worker frame machinery, kept byte-for-byte. 'ropchain' is the
// pthread-backed Civ 7 backend (historical default — see below). 'rawsvc' is
// the hardware-qualified Civ 7 backend: the same buildRop() chains and forged
// jmp_buf, but launched through the civswitch-kit raw svcCreateThread path
// (civshim ops 12-15) because pthread_create silently no-ops and
// nn::os::CreateThread hangs on Civ 7 1.0.0 — docs/CIVSWITCH-INTEGRATION.md
// §2c. The host compiles each worker's call list into a linear ROP chain plus
// a forged jmp_buf with shared/frames.cjs buildRop(), WRITEs the buffer, then
// drives it through the civshim THREAD CREATE / THREAD JOIN ops
// (pthread_create(&t, NULL, longjmp, jb)).
// Protocol: payloads/civshim.js ops 8/9 (ropchain), 12-15 (rawsvc).
// Config: BARBARISM_WORKER.
// Origin: ported from ns2jb engine/switch2/app/native-worker.cjs, adapted
// for BarbarismJB — see `// barbarism:` markers.
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const {live, check} = require("./session.cjs");
const transport = require('../../shared/rpc.cjs');
const config = require('../../shared/config.cjs');
const {nativeHash} = require("./filesystem.cjs");
const {code, SENTINEL} = require("./worker.cjs");
const {build, buildRop} = require('../../shared/frames.cjs');

const backend = config.workerBackend();
const align = n => Math.ceil(n / 4096) * 4096;
// barbarism: raw-svc constants from the civswitch-kit hardware run
// (docs/CIVSWITCH-INTEGRATION.md §2c): 0x14000-byte raw stacks
// (target.civ7.json thread.stackBytes 81920) and the kernel wait-sync timeout
// result 0xEA01 (kit CHANGES.md patch 1 — 0xE901 was the author's typo).
const RAW_STACK_BYTES = 0x14000;
const RAW_WAIT_TIMEOUT = 59905;
function capacity(calls) {
  const count = calls.reduce((n, call) => n + 1 + call.args.filter(a => typeof a === 'object').length, 0);
  return align(0x20000 + count * 0x300);
}

async function writeSparse(s, address, bytes) {
  check(address % 8 === 0 && bytes.length % 8 === 0 && address >= s.base && address + bytes.length <= s.base + s.bytes,
    'Sparse write is outside the owned allocation');
  // start() has already cleared the whole allocation. Send only occupied
  // pages; the native hash below still checks every byte, including zeroes.
  let first = null;
  for (let offset = 0; offset <= bytes.length; offset += 4096) {
    const occupied = offset < bytes.length && bytes.subarray(offset, offset + 4096).some(Boolean);
    if (occupied && first === null) first = offset;
    if (!occupied && first !== null) {
      await s.write(address + first, bytes.subarray(first, offset));
      first = null;
    }
  }
}

// barbarism: the jmp_buf layout and gadget addresses resolve from the offsets
// table once per process; a missing or mangled layout fails loudly here.
function ropContext() {
  if (!ropContext.cached) {
    const {parseJmpBuf} = require('../../lib/offsets.cjs');
    const table = live.offsets || {};
    ropContext.cached = {jmpBuf: parseJmpBuf(table.jmp_buf), gadgets: live.gadgets};
  }
  return ropContext.cached;
}

async function start(s, base, limit, slot, calls, label, snapshot = 0) {
  check(base % 4096 === 0 && base >= s.base && base + limit <= s.base + s.bytes, 'Worker frame is outside allocation');
  check(slot % 8 === 0 && slot >= s.base && slot + 16 <= base, 'Worker output slot overlaps its frame');
  const plan = path.join(__dirname, label + '-plan.json'), filename = path.join(__dirname, label + '-frame.bin');
  await fs.writeFile(plan, JSON.stringify({base, sdk: live.sdk, backend, calls}) + '\n');
  let built;
  if (backend === 'frames')
    built = build(base, live.sdk, calls, code);
  else if (backend === 'rawsvc')
    // barbarism: raw kernel threads have no musl TCB — the chain tail is the
    // svc #0x0A wrapper (svc.exit_thread), never pthread_exit.
    built = buildRop(base, {...live, workerExit: live.svc?.exit_thread}, calls,
      ropContext().jmpBuf, ropContext().gadgets);
  else
    built = buildRop(base, live, calls, ropContext().jmpBuf, ropContext().gadgets);
  const {frame, proof} = built;
  await fs.writeFile(filename, frame, {flag: 'wx', mode: 0o600});
  check(frame.length === proof.bytes && frame.length <= limit, 'Worker frame exceeds reserved space');
  const hash = crypto.createHash('sha256').update(frame).digest('hex');
  if (backend === 'frames') {
    await s.call('memset', base, 0, limit);
    await writeSparse(s, base, frame);
    check(await nativeHash(s, base, frame.length) === hash, 'Full worker frame hash differs');
    if (snapshot) {
      check(snapshot >= base + limit && snapshot + frame.length <= s.base + s.bytes, 'Worker snapshot is outside allocation');
      await s.rpc.call3(live.sdk + 0x586fb0, snapshot, base, frame.length);
      check(await nativeHash(s, snapshot, frame.length) === hash, 'Worker snapshot differs');
    }
  } else {
    // barbarism: no SDK memset/hash pins assumed — write the whole buffer through
    // the zero-copy WRITE path and verify by full read-back instead.
    await s.rpc.write(base, frame);
    check((await s.rpc.read(base, frame.length)).equals(frame), 'Ropchain worker read-back differs');
  }
  await s.record({operation: 'workerPrepared', label, base, slot, backend, ...proof, frameSha256: hash});
  return launch(s, {label, base, slot, calls, ...proof, snapshot, frameSha256: hash, frameBytes: frame});
}

async function launch(s, prepared) {
  const {label, base, slot} = prepared;
  await s.write(slot, Buffer.alloc(16));
  const pending = label + ':creating';
  s.threads.add(pending);
  let thread;
  if (backend === 'frames') {
    const result = await s.rpc.call4(live.sdk + code.create.offset, slot, 0, live.sdk + code.longjmp.offset, base);
    if (result) s.threads.delete(pending);
    check(!result, 'pthread_create failed: ' + result);
    thread = Number((await s.readOwned(slot, 8)).readBigUInt64LE());
  } else if (backend === 'rawsvc') {
    // barbarism: raw svcCreateThread launch — the civswitch-kit
    // hardware-qualified path (nn::os::CreateThread hangs; pthread_create
    // silently no-ops on Civ 7 1.0.0). Entry is longjmp with the forged
    // jmp_buf/chain at base, exactly what their raw-thread frame probe
    // validated. The stack is a dedicated game calloc (zeroed, disjoint from
    // every arena — kit FINDINGS §2.2 rule), so it can never overlap the
    // frame or snapshot.
    if (!s.rawScheduling) {
      const borrowed = await transport.request({command: 'thread-sched-borrow'});
      check(Number.isSafeInteger(borrowed.priority) && borrowed.priority > 0 && borrowed.priority < 64,
        'Invalid borrowed thread priority');
      const cores = [];
      const mask = BigInt(borrowed.coreMask);
      for (let bit = 0n; bit < 64n; bit++) if ((mask >> bit) & 1n) cores.push(Number(bit));
      check(cores.length, 'Borrowed thread core mask is empty');
      s.rawScheduling = {priority: borrowed.priority, cores};
      await s.record({operation: 'rawSchedulingBorrowed', priority: borrowed.priority,
        cores, manager: borrowed.manager, nodes: borrowed.nodes});
    }
    let stack = prepared.rawStack;
    if (!stack) {
      stack = (await transport.request({command: 'alloc', size: RAW_STACK_BYTES})).address;
      check(Number.isSafeInteger(stack) && stack > 0 && stack % 0x1000 === 0,
        'Raw stack allocation is not page-aligned guest memory');
    } else {
      await s.rpc.write(stack, Buffer.alloc(RAW_STACK_BYTES)); // re-zero for a relaunch
    }
    prepared.rawStack = stack; // travels with the worker through restart()
    const stackTop = stack + RAW_STACK_BYTES;
    let created = null;
    for (const core of s.rawScheduling.cores) {
      const reply = await transport.request({command: 'thread-create-raw',
        jbPtr: base, stackTop, priority: s.rawScheduling.priority, core});
      if (reply.handle) {created = reply; break;}
      check(reply.createResult === 0xe001,
        'svcCreateThread failed: 0x' + (reply.createResult || reply.startResult || 0).toString(16));
      await s.record({operation: 'rawThreadCreateAttempt', label, core, result: reply.createResult});
    }
    if (!created) s.threads.delete(pending);
    check(created, 'svcCreateThread rejected every borrowed core');
    thread = created.thread;
    const stored = Buffer.alloc(8);
    stored.writeBigUInt64LE(BigInt(thread));
    await s.write(slot, stored);
  } else {
    // barbarism: civshim THREAD_CREATE — pthread_create(&slot, NULL, longjmp,
    // jb=base) driven on-console; the pthread_t comes back in the reply and is
    // mirrored into the worker slot for downstream symmetry.
    const reply = await transport.request({command: 'thread-create', jbPtr: base, stackTop: 0});
    thread = Number(reply.thread);
    if (!thread) s.threads.delete(pending);
    const stored = Buffer.alloc(8);
    stored.writeBigUInt64LE(BigInt(thread));
    await s.write(slot, stored);
  }
  if (backend === 'rawsvc')
    check(Number.isSafeInteger(thread) && thread > 0 && thread < 0xffff8000, 'Invalid raw thread handle');
  else
    check(Number.isSafeInteger(thread) && thread > 0 && thread < 2 ** 39 && thread % 8 === 0, 'Invalid worker pointer');
  s.threads.delete(pending); s.threads.add(thread);
  const worker = {...prepared, thread, joined: false};
  check((await s.readOwned(base + worker.resultOffset, 8)).readBigUInt64LE() === SENTINEL, 'Worker passed its start gate');
  await s.record({operation: 'workerStarted', label, thread, base, backend});
  return worker;
}

async function restart(s, worker) {
  // A joined thread's address can already belong to another worker.
  check(worker.snapshot && worker.joined, 'Cannot restore an active worker');
  if (backend === 'frames') {
    await s.rpc.call3(live.sdk + 0x586fb0, worker.base, worker.snapshot, worker.bytes);
  } else {
    // barbarism: the host kept the exact frame bytes, so a restart rewrites the
    // chain (fresh SENTINELs included) instead of restoring a console-side
    // snapshot. The snapshot parameter is not needed and is ignored.
    await s.rpc.write(worker.base, worker.frameBytes);
  }
  delete worker.results;
  return launch(s, worker);
}

async function join(s, worker, timeoutMs = 15000) {
  check(!worker.joined && s.threads.has(worker.thread), 'Worker is not owned');
  let finished;
  if (backend === 'frames') {
    const until = Date.now() + timeoutMs;
    do {
      finished = await s.rpc.call3(live.sdk + code.tryWait.offset, worker.thread, 0, 0);
      check(finished === 0 || finished === 1, 'Unexpected thread state');
      if (finished) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    } while (Date.now() < until);
  } else if (backend === 'rawsvc') {
    // barbarism: poll the kernel handle with single-shot svcWaitSynchronization
    // (civshim op 13). 0 = signaled; 0xEA01 = wait timeout (poll again — the
    // kit's join poll, kit CHANGES.md patch 1); anything else is fatal. The
    // host-side 10 ms pacing keeps the console JS thread free between polls.
    const until = Date.now() + timeoutMs;
    do {
      const wait = await transport.request({command: 'thread-wait', thread: worker.thread, timeoutNs: 0});
      check(wait.result === 0 || wait.result === RAW_WAIT_TIMEOUT,
        'Unexpected wait-synchronization result: 0x' + wait.result.toString(16));
      if (wait.result === 0) {
        check(wait.index === 0, 'Wait signaled a different handle');
        finished = 1;
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 10));
    } while (Date.now() < until);
  } else {
    // barbarism: no tryjoin pin for Civ 7 yet, so join() blocks on-console inside
    // civshim THREAD_JOIN. The worker never re-enters the JS thread, so this
    // is safe; the bridge's 180s never-replay timeout is the hard stop.
    await transport.request({command: 'thread-join', thread: worker.thread});
    finished = 1;
  }
  check(finished, 'Native batch did not terminate; resources retained');
  const raw = await s.readOwned(worker.base + worker.resultOffsets[0], worker.resultOffsets.length * 8);
  const values = worker.resultOffsets.map((_, i) => raw.readBigUInt64LE(i * 8));
  check(values.every(value => value !== SENTINEL), 'Native batch did not store every result');
  if (backend === 'frames') {
    check(!await s.rpc.call3(live.sdk + code.join.offset, worker.thread, worker.slot + 8, 0), 'pthread_join failed');
    check((await s.readOwned(worker.slot + 8, 8)).readBigUInt64LE() === values.at(-1), 'Thread exit result differs');
  }
  if (backend === 'rawsvc') {
    const closed = await transport.request({command: 'thread-close', thread: worker.thread});
    check(!closed.result, 'svcCloseHandle failed: 0x' + (closed.result || 0).toString(16));
  }
  s.threads.delete(worker.thread);
  worker.joined = true;
  worker.results = worker.logicalResultIndices.map(i => values[i]);
  await s.record({operation: 'workerJoined', label: worker.label, thread: worker.thread,
    values: worker.results.map(String), nativeCalls: values.length});
  return worker.results;
}

// barbarism: park workers that are mid-chain (setup cancellation). The frames
// backend overwrote the next dispatch-table entry with the SDK exit function;
// the ropchain backend rewrites EVERY call cell to pthread_exit; the rawsvc
// backend rewrites every cell to the svc #0x0A wrapper (svcExitThread) — a raw
// kernel thread has no musl TCB, so pthread_exit would fault it (civswitch-kit
// thread-code.json directNnOs.pthreadExit). svc #0x07 is svcExitProcess and
// would kill the game. Already-executed cells are harmless; a running worker
// exits at its next call.
async function cancelAll(s, workers) {
  if (backend === 'frames') {
    for (const worker of workers)
      await s.rpc.store64(worker.base + worker.tablesOffset +
        worker.logicalResultIndices[1] * 0x100 + 0x78, BigInt(live.sdk + code.exit.offset));
    return;
  }
  const exitAddress = backend === 'rawsvc' ? live.svc.exit_thread : live.sdkFn.pthread_exit;
  check(Number.isSafeInteger(exitAddress) && exitAddress > 0,
    (backend === 'rawsvc' ? 'svc.exit_thread' : 'pthread_exit') + ' offset missing for cancellation');
  for (const worker of workers) {
    const count = worker.nativeCalls + 1;
    for (let index = 0; index < count; index++)
      await s.rpc.store64(worker.base + worker.cellsOffset + index * worker.cellStride + 8 + 0x18,
        BigInt(exitAddress));
  }
}

async function restartAll(s, workers) {
  for (const worker of workers) Object.assign(worker, await restart(s, worker));
  return workers;
}

async function joinAll(s, workers, timeoutMs = 15000) {
  for (const worker of workers) await join(s, worker, timeoutMs);
}

module.exports = {capacity, writeSparse, start, restart, join, restartAll, joinAll, cancelAll, backend};
