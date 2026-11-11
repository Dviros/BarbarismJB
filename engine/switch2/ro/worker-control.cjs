// barbarism: PORTED to the offsets table (was: SmileBASIC sdk-functions.json
// getService/send pins, a hardcoded CancelSynchronization fingerprint, and the
// SmileBASIC event pins, behind loud unported() guards). Mapping:
//   send         -> live.svc.send_sync_request (Switch 2 svcSendSyncRequest
//                   signature x0=buffer, x1=size, x2=handle — the same entry
//                   session.cjs 'send' uses; REQUIRED in offsets/civ7-100.json)
//   app-service  -> live.svc.connect_to_named_service: one native call per
//                   service name replaces the SmileBASIC SDK getService
//                   wrapper; the session handle returns in x0, i.e. directly
//                   into the worker's result slot (hardware-proven shape:
//                   session.cjs smSession on 23.0.1)
//   cancel       -> svc.cancel_synchronization from the offsets table
//                   (Switch 2 svc 0x19: the SmileBASIC table's pinned wrapper
//                   bytes '210300d4c0035fd6' execute `svc #0x19; ret`). The
//                   exported cancelCode keeps the verifyCode {offset, bytes}
//                   shape consumed by retained/retained-memory.cjs by
//                   self-pinning at runtime: the unique `svc #0x19` site
//                   inside the wrapper window is located and pinned exactly
//                   once (the ro/control.cjs 'event-signal' discovery pattern).
//   gate         -> app/events.cjs (offsets-driven since the events port)
//   finished     -> frames backend keeps the SmileBASIC tryjoin pin; the
//                   ropchain backend probes the worker's result slots: the
//                   chain is finished when every stored slot has left the
//                   SENTINEL state (the same probe native-worker.cjs join()
//                   trusts).
const path = require('node:path');
const {packet, response} = require("../../shared/ipc.cjs");
const {fail} = require('../../shared/errors.cjs');
const {live} = require("../app/session.cjs");
const nativeOffsets = require('../app/native-offsets.cjs');
const check = (ok, message) => { if (!ok) throw Error(message); };

// `svc #0x19; ret` — Switch 2 CancelSynchronization (see offsets/README.md).
const cancelSite = '210300d4', cancelBytes = cancelSite + 'c0035fd6';

// barbarism: runtime self-pin for the CancelSynchronization wrapper. The
// offsets entry points at the wrapper; the callable+verifiable site is the
// unique `svc #0x19` instruction inside it. Cached for the process lifetime.
let cancelPin = null;
async function resolveCancel(s) {
  if (cancelPin) return cancelPin;
  const entry = nativeOffsets.svcOffset(live, 'cancel_synchronization');
  const window = await s.read(live.sdk + entry, 0x80);
  const needle = Buffer.from(cancelSite, 'hex');
  const found = window.indexOf(needle);
  check(found >= 0 && found % 4 === 0 && found === window.lastIndexOf(needle),
    'The CancelSynchronization wrapper does not contain a unique svc #0x19 site — re-check svc.cancel_synchronization in offsets/civ7-100.json');
  cancelPin = {offset: entry + found, bytes: cancelBytes};
  await s.verifyCode(cancelPin, 'CancelSynchronization');
  return cancelPin;
}

async function cancelWorkers(context) {
  const {s, live, report} = context;
  const workers = report.nativeRo.apiWorkers;
  check(workers?.length === 7 && workers.every(w => s.handles.has(w.handle)), 'API-worker copies are missing');
  const pin = await resolveCancel(s);
  const replies = await s.rpc.batch(workers.map(w => ({fn: live.sdk + pin.offset, args: [w.handle, 0, 0]})));
  return replies.map((r, i) => ({handle: workers[i].handle, result: r.result}));
}

async function dispatch(context, request, state, domain) {
  const {s, live, save} = context;
  const directory = path.join(__dirname, '../app');
  const native = require(path.join(directory, 'native-worker.cjs'));
  const events = require(path.join(directory, 'events.cjs'));
  const workerCode = require(path.join(directory, 'worker.cjs'));
  const command = request.command.slice('root-native-'.length);
  if (command === 'worker-bind') {
    const rows = request.workers;
    check(Array.isArray(rows) && rows.length === 7 && new Set(rows.map(w => w.handle)).size === 7,
      'Expected seven different native API-worker copies');
    check(rows.every(w => state.events.some(e => e.handle === w.handle) && s.handles.has(w.handle) &&
      state.calls.some(e => e.operation === 'thread-id' && e.handle === w.handle && e.result === 0 && Number(e.value) === w.id)),
      'Worker copies lack their native thread-ID checks');
    await resolveCancel(s);
    state.apiWorkers = rows;
    await save();
    return rows;
  }
  if (command === 'worker-cancel') {
    const replies = await cancelWorkers(context);
    (state.cancellations ||= []).push({at: new Date().toISOString(), replies});
    await save();
    check(replies.every(r => r.result === 0), 'Foreign thread cancellation was rejected');
    return replies;
  }
  if (command === 'worker-prepare') {
    check(!s.threads.size && (!state.worker || state.worker.joined), 'A native worker is still active');
    await workerCode.verifyWorkerCode(s);
    await events.verify(s);
    const area = s.base + 0x2100000, gate = area, slot = area + 0x10;
    check(area + 0x60000 <= s.base + s.bytes, 'Worker area exceeds the retained allocation');
    await events.initialize(s, gate);
    const handle = Number(request.handle);
    check(request.kind === 'app-service' || s.handles.has(handle), 'Worker IPC requires a retained caller handle');
    const batchInputs = request.kind === 'notifier-probe' && request.candidates;
    if (batchInputs) check(Array.isArray(batchInputs) && batchInputs.length > 0 && batchInputs.length <= 16 &&
      batchInputs.every(n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff), 'Expected 1..16 candidate handles');
    const count = batchInputs ? batchInputs.length : request.kind === 'control-test' ? 2 : 1;
    const upload = batchInputs ? Buffer.alloc(count * 0x1000) : null;
    check(['control-test', 'cmif-control', 'pm-launch', 'sm-get', 'app-service', 'ro-probe', 'ro-process', 'notifier-probe'].includes(request.kind), 'Unknown worker operation');
    const calls = [{function: live.sdk + events.code.wait.offset, args: [gate, 0, 0, 0]}];
    for (let i = 0; i < count; i++) {
      let bytes;
      const address = area + 0x1000 * (i + 1);
      if (request.kind === 'app-service') {
        check(typeof request.name === 'string' && /^[a-z0-9:-]{1,8}$/.test(request.name), 'Invalid application service name');
        // barbarism: svcConnectToNamedService replaces the SmileBASIC SDK
        // getService wrapper — one native call; the handle returns in x0.
        bytes = Buffer.alloc(16); bytes.write(request.name, 0);
        await s.write(address, bytes);
        calls.push({function: live.svc.connect_to_named_service,
          args: [address, request.name.length, 0, 0]});
        continue;
      } else if (request.kind === 'cmif-control') {
        const service = state.services.find(item => item.handle === handle);
        check(service && ['fsp-srv', 'spl:fs', 'pm:dmnt'].includes(service.name) &&
          [0, 3].includes(request.id), 'Expected an owned qualification session and manager command 0 or 3');
        bytes = domain.wire.control(request.id);
      } else if (request.kind === 'control-test') bytes = domain.wire.control(3);
      else if (request.kind === 'sm-get') {
        check(state.services.some(x => x.sm === handle) && typeof request.name === 'string' &&
          /^[a-z0-9:-]{1,8}$/.test(request.name), 'SM worker requires the established borrowed client and a service name');
        bytes = Buffer.alloc(256); bytes.writeUInt32LE(0x11); bytes.writeUInt32LE(2, 4); bytes.write(request.name, 8);
      } else if (request.kind === 'ro-probe') {
        check(typeof request.hex === 'string' && /^[0-9a-fA-F]{16}$/.test(request.hex), 'RO proof needs one 64-bit challenge');
        bytes = packet(0x524f0001, Buffer.from(request.hex, 'hex'));
      } else if (request.kind === 'ro-process') {
        const target = Number(request.processHandle), id = Number(request.id);
        check(state.services.some(x => x.name === 'ro:dmnt' && x.handle === handle), 'Process probe requires the owned RO service');
        check(s.handles.has(target) || target === 0xffff8001, 'Target process handle is not owned');
        check([0x524f0010, 0x524f0011, 0x524f0012, 0x524f0013, 0x524f0014,
          0x524f0015, 0x524f0016].includes(id), 'Unknown process probe');
        const size = id === 0x524f0014 ? 128 : 64;
        check(typeof request.hex === 'string' && request.hex.length === size && /^[0-9a-fA-F]+$/.test(request.hex),
          'Process probe input length differs');
        const receive = [];
        if (id === 0x524f0016) {
          const length = Number(Buffer.from(request.hex, 'hex').readBigUInt64LE(16));
          const output = s.base + 0x1800000;
          check(Number.isInteger(length) && length > 0 && length <= 0x400000 &&
            output + length <= s.base + s.bytes, 'Bulk RO read exceeds the owned buffer');
          receive.push({address: output, size: length});
        }
        bytes = packet(id, Buffer.from(request.hex, 'hex'), {pid: true, copies: [target], receive});
      } else if (request.kind === 'notifier-probe') {
        check(state.notifiers.includes(handle), 'Native execution probe requires our owned FS notifier');
        const input = Buffer.alloc(batchInputs ? 4 : 0);
        if (batchInputs) input.writeUInt32LE(batchInputs[i]);
        bytes = packet(0, input);
      } else {
        check(state.services?.some(x => x.name === 'pm:shell' && x.handle === handle), 'Launch requires the owned PM session');
        const flags = Number(request.flags ?? 0);
        check(flags === 0 || flags === 0x10, 'Unsupported launch flags');
        const storage = Number(request.storage ?? 3);
        check(storage === 3 && request.title === '0x0400000000000037',
          'Only the qualified RO replacement may be launched');
        const input = Buffer.alloc(24); input.writeUInt32LE(flags);
        input.writeBigUInt64LE(BigInt(request.title), 8); input[16] = storage;
        bytes = packet(0, input);
      }
      if (upload) bytes.copy(upload, i * 0x1000);
      else await s.write(address, bytes);
      // barbarism: the SmileBASIC SDK send wrapper maps to the raw
      // svcSendSyncRequest wrapper from the offsets table.
      calls.push({function: live.svc.send_sync_request,
        args: [address, 4096, handle, 0]});
    }
    if (upload) await s.write(area + 0x1000, upload);
    state.worker = await native.start(s, area + 0x20000, 0x40000, slot, calls,
      'ro-' + request.kind + '-' + Date.now());
    Object.assign(state.worker, {kind: request.kind, handle, gate, area, count, released: false,
      serviceName: request.name, challenge: request.hex, candidates: batchInputs || undefined,
      processCommand: request.kind === 'ro-process' ? Number(request.id) : undefined,
      launchTitle: request.kind === 'pm-launch' ? request.title : undefined,
      launchFlags: request.kind === 'pm-launch' ? Number(request.flags ?? 0) : undefined});
    await save();
    return {kind: state.worker.kind, thread: state.worker.thread, gate, count};
  }
  const worker = state.worker;
  check(worker && !worker.joined && s.threads.has(worker.thread), 'No active native worker');
  if (command === 'worker-discard-unreleased-launch') {
    check(worker.kind === 'pm-launch' && worker.launchTitle === '0x0400000000000037' &&
      worker.launchFlags === 0x10 && !worker.released, 'Only this unreleased helper launch may be discarded');
    const before = await s.readOwned(worker.area + 0x1000, 256);
    check(before.readUInt32LE() === 4 && before.toString('ascii', 16, 20) === 'SFCI' &&
      before.readUInt32LE(24) === 0, 'The pending request is not the prepared PM launch');
    // Replace the not-yet-issued launch with the read-only application-PID query.
    await s.write(worker.area + 0x1000, packet(6));
    worker.discardedLaunch = before.toString('hex'); await save();
    return {discarded: true};
  }
  if (command === 'worker-release') {
    check(!worker.released, 'Worker start gate was already released');
    await events.signal(s, worker.gate);
    worker.released = true;
    await save();
    return {released: true};
  }
  if (command === 'worker-state' || command === 'worker-join') {
    let finished;
    if (native.backend === 'frames') {
      finished = await s.rpc.call3(live.sdk + workerCode.code.tryWait.offset, worker.thread, 0, 0);
    } else {
      // barbarism: no Civ 7 tryjoin pin — the ropchain worker is finished when
      // every result slot has left the SENTINEL state (native-worker.cjs join
      // applies the same probe before joining).
      const raw = await s.readOwned(worker.base + worker.resultOffsets[0], worker.resultOffsets.length * 8);
      finished = worker.resultOffsets.every((_, i) => raw.readBigUInt64LE(i * 8) !== workerCode.SENTINEL) ? 1 : 0;
    }
    const raw = await s.readOwned(worker.base + worker.resultOffsets[0], worker.resultOffsets.length * 8);
    const values = worker.logicalResultIndices.map(i => raw.readBigUInt64LE(i * 8).toString());
    const result = {finished: !!finished, values, sentinel: workerCode.SENTINEL.toString()};
    if (command === 'worker-join') {
      check(finished, 'Worker is still pending');
      await native.join(s, worker, 1000);
      worker.results = worker.results.map(String);
      result.responses = [];
      for (let i = 0; i < worker.count; i++) {
        const raw = await s.readOwned(worker.area + 0x1000 * (i + 1), 256);
        if (worker.kind === 'app-service') {
          // barbarism: svcConnectToNamedService returns the session handle in
          // x0 (the worker's result slot), not in the staged buffer.
          const handle = Number(values[i + 1]);
          check(handle > 0 && handle < 0xffff8000, 'svcConnectToNamedService returned no session handle');
          s.handles.add(handle);
          state.services.push({name: worker.serviceName, handle, application: true});
          result.responses.push({result: 0, handle, raw: raw.subarray(0, 32).toString('hex')});
        } else if (values[i + 1] !== '0') { result.responses.push({transport: Number(values[i + 1]), raw: raw.toString('hex')}); continue; }
        else if (worker.kind === 'sm-get') {
          check(raw.readUInt32LE() === 0x11 && raw.readUInt32LE(4) === 0x80000001 &&
            raw.readUInt32LE(8) === 0x20, 'Unexpected native SM reply');
          const handle = raw.readUInt32LE(12), status = raw.readUInt32LE(16);
          const reply = {result: status, handle, raw: raw.subarray(0, 32).toString('hex')};
          result.responses.push(reply);
          if (!status) {
            check(handle > 0, 'SM returned a null session');
            s.handles.add(handle);
            state.services.push({name: worker.serviceName, handle, sm: worker.handle});
          }
        } else {
          const reply = response(raw);
          if (worker.kind === 'notifier-probe') {
            for (const handle of [...reply.copies, ...reply.moves]) {
              s.handles.add(handle); state.events.push({handle, operation: 'notifier-probe'});
            }
          }
          if (worker.kind === 'control-test') {
            for (const handle of [...reply.copies, ...reply.moves]) {
              s.handles.add(handle);
              (state.domainCopies ||= []).push({handle, domainHandle: worker.handle, controlTest: true});
            }
          }
          const kernelPid = raw.readUInt32LE(4) >>> 31 && raw.readUInt32LE(8) & 1 ?
            raw.readBigUInt64LE(12).toString() : null;
          result.responses.push({...reply, kernelPid, data: reply.data.toString('hex'), raw: raw.toString('hex')});
          if (worker.processCommand === 0x524f0016 && !reply.result) {
            const length = Number(Buffer.from(worker.challenge, 'hex').readBigUInt64LE(16));
            check(Number(reply.data.readBigUInt64LE(48)) === length, 'RO bulk output length differs');
            const bulk = require(path.join(directory, 'bulk-transfer.cjs'));
            const data = await bulk.read(s, s.base + 0x1800000, length);
            const fs = require('node:fs/promises'), crypto = require('node:crypto');
            const outputFile = path.join(__dirname,
              live.session + '-ro-bulk-' + Date.now() + '.bin');
            await fs.writeFile(outputFile, data, {mode: 0o600});
            Object.assign(result.responses.at(-1), {outputFile, length,
              sha256: crypto.createHash('sha256').update(data).digest('hex')});
          }
        }
      }
      await events.finalize(s, worker.gate);
      worker.completion = result;
      await save();
    }
    return result;
  }
  throw Error('Unknown native worker command');
}

module.exports = {dispatch, cancelWorkers,
  // barbarism: retained/retained-memory.cjs verifies this pin; resolveCancel()
  // (worker-bind / worker-cancel / any launch-stage worker command) fills it.
  // Accessing it before resolution fails loudly with the exact missing key.
  get cancelCode() {
    if (!cancelPin)
      throw fail('E_OFFSETS', 'svc.cancel_synchronization has not been resolved yet — run a launch-stage worker command (worker-bind/worker-cancel resolve the CancelSynchronization pin) after filling svc.cancel_synchronization in offsets/civ7-100.json (svc 0x19; offsets/README.md)');
    return cancelPin;
  }};
