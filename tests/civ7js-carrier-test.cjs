// tests/civ7js-carrier-test.cjs — offline verification of the CivSwitch
// carrier layer (engine/carrier/civ7js/): the :9026 loader client against a
// fake loader over real loopback sockets (half-close discipline, log
// streaming, marker wait, idle timeout, empty-payload refusal), the carrier
// baker (offsets embedded, syntax-valid output, anchor-drift detection), and
// the civswitch-kit offsets importer against a minimal fixture kit.
//
// The civshim ops 12-15 round-trips live in tests/civshim-sim.cjs (the
// console-side simulation). This suite is the host-side half.
// Origin: original — BarbarismJB.
// Run: node tests/civ7js-carrier-test.cjs   (exit 0 = all scenarios passed)
'use strict';
const net = require('node:net');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert');
const {execFileSync} = require('node:child_process');

const PROJECT = path.resolve(__dirname, '..');
const {sendPayload, sendAndAwait} = require(path.join(PROJECT, 'engine/carrier/civ7js/loader-client.cjs'));
const {buildCarrier} = require(path.join(PROJECT, 'engine/carrier/civ7js/build-carrier.cjs'));
const {importKit} = require(path.join(PROJECT, 'engine/carrier/civ7js/import-civswitch-offsets.cjs'));

let passed = 0;
async function step(name, body) {
  try {await body(); passed++; console.log('  ok  ' + name);}
  catch (error) {console.error('  FAIL ' + name + ': ' + (error.stack || error.message)); throw error;}
}

// A fake :9026 loader: on connect it collects bytes until the client
// half-closes, then (optionally) streams log lines and closes. allowHalfOpen
// models the real loader, which keeps streaming its log channel for minutes
// after the push client shuts down its write side.
function fakeLoader({onPayload, delayCloseMs = 0, keepOpen = false} = {}) {
  const events = [];
  const server = net.createServer({allowHalfOpen: true}, socket => {
    let received = Buffer.alloc(0), sawEnd = false;
    socket.on('data', chunk => {received = Buffer.concat([received, chunk]);});
    socket.on('end', () => {
      sawEnd = true;
      events.push({payload: received, halfClosed: true});
      if (onPayload) onPayload(received, socket);
      if (!keepOpen) setTimeout(() => socket.end(), delayCloseMs);
    });
    socket.on('error', () => {});
  });
  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => resolve({server, events, port: server.address().port}));
  });
}

async function main() {
  console.log('civ7js-carrier-test: loader client, carrier builder, offsets import');

  await step('loader client: payload delivered + half-close + log stream', async () => {
    const loader = await fakeLoader({onPayload: (_, socket) => socket.write('log line 1\nlog line 2\n')});
    const result = await sendPayload({host: '127.0.0.1', port: loader.port,
      payload: '// test payload', idleTimeoutMs: 2000});
    assert.strictEqual(result.bytes, 15);
    assert.ok(result.logs.includes('log line 1') && result.logs.includes('log line 2'));
    assert.strictEqual(loader.events[0].halfClosed, true, 'client must half-close after sending');
    assert.ok(loader.events[0].payload.equals(Buffer.from('// test payload')));
    loader.server.close();
  });

  await step('loader client: refuses an empty payload (bad-connection discipline)', async () => {
    await assert.rejects(() => sendPayload({host: '127.0.0.1', port: 65001, payload: ''}),
      error => error.code === 'E_ARGS');
    await assert.rejects(() => sendPayload({host: '127.0.0.1', port: 65001}),
      error => error.code === 'E_ARGS');
  });

  await step('loader client: connect failure is E_LOADER_CONNECT', async () => {
    await assert.rejects(() => sendPayload({host: '127.0.0.1', port: 65001, payload: 'x',
      connectTimeoutMs: 500}), error => error.code === 'E_LOADER_CONNECT');
  });

  await step('loader client: onLog streams chunks as they arrive', async () => {
    const seen = [];
    const loader = await fakeLoader({keepOpen: true, onPayload: (_, socket) => {
      socket.write('first\n'); setTimeout(() => socket.write('second\n'), 50);
      setTimeout(() => socket.end(), 150);
    }});
    await sendPayload({host: '127.0.0.1', port: loader.port, payload: 'p',
      idleTimeoutMs: 5000, onLog: text => seen.push(text)});
    // TCP may coalesce the two writes; assert stream CONTENT and that the
    // callback fired (not exact chunk boundaries).
    assert.ok(seen.length >= 1);
    assert.strictEqual(seen.join(''), 'first\nsecond\n');
    loader.server.close();
  });

  await step('loader client: idle timeout resolves closedEarly for long-running payloads', async () => {
    const loader = await fakeLoader({keepOpen: true}); // never closes the stream
    const result = await sendPayload({host: '127.0.0.1', port: loader.port, payload: 'p',
      idleTimeoutMs: 300});
    assert.strictEqual(result.closedEarly, true, 'idle timeout must resolve the promise');
    loader.server.close();
  });

  await step('sendAndAwait: resolves on the marker with the stream still open', async () => {
    const loader = await fakeLoader({keepOpen: true, onPayload: (_, socket) => {
      socket.write('booting...\n');
      setTimeout(() => socket.write('civshim: listening on :39381\n'), 40);
    }});
    const result = await sendAndAwait({host: '127.0.0.1', port: loader.port, payload: 'p',
      markers: ['civshim: listening on :39381'], idleTimeoutMs: 5000});
    assert.strictEqual(result.marker, 'civshim: listening on :39381');
    loader.server.close();
  });

  await step('sendAndAwait: stream close without the marker is an error', async () => {
    const loader = await fakeLoader({onPayload: (_, socket) => socket.write('died instantly\n')});
    await assert.rejects(() => sendAndAwait({host: '127.0.0.1', port: loader.port, payload: 'p',
      markers: ['civshim: listening on :39381'], idleTimeoutMs: 5000}),
      error => error.code === 'E_LOADER_CLOSED' && /died instantly/.test(error.message));
    loader.server.close();
  });

  const shimSource = await fs.readFile(path.join(PROJECT, 'payloads', 'civshim.js'), 'utf8');
  const offsetsFixture = {
    svc: {query_memory: 1477388, send_sync_request: 1477716, sleep_thread: 1274112,
      close_handle: 1477604, create_thread: 1477420, start_thread: 1477444,
      wait_synchronization: 1477620, get_thread_priority: 1477468, get_thread_core_mask: 1477500},
    sdk_offsets: {longjmp: 5575092, thread_manager_global: 11674240},
    modules: {sdk: {size: 6299648}}
  };

  await step('build-carrier: bakes the offsets dict and the port', async () => {
    const built = buildCarrier({shimSource, offsetsTable: offsetsFixture, shimPort: 39401});
    assert.ok(/query_memory:\s+1477388,/.test(built.carrier), 'svc value baked');
    assert.ok(/thread_manager_global:\s+11674240,/.test(built.carrier), 'sdk value baked');
    assert.ok(/PORT:\s*39401,/.test(built.carrier), 'port baked');
    assert.ok(/connect_to_named_service:\s+null,/.test(built.carrier), 'unknown stays null');
    assert.strictEqual(built.filled.svc, 9);
    assert.strictEqual(built.filled.sdk_offsets, 2);
    assert.strictEqual(built.port, 39401);
  });

  await step('build-carrier: output is valid JavaScript (node --check)', async () => {
    const built = BuildNull(); // helper below builds with the null table
    const file = path.join(os.tmpdir(), 'barbarism-carrier-check-' + process.pid + '.js');
    await fs.writeFile(file, built.carrier);
    execFileSync(process.execPath, ['--check', file], {stdio: 'pipe'});
    await fs.rm(file);
    function BuildNull() {return buildCarrier({shimSource, offsetsTable: {svc: {}, sdk_offsets: {}}, shimPort: undefined});}
  });

  await step('build-carrier: source drift fails loudly (E_CARRIER_ANCHOR)', async () => {
    const drifted = shimSource.replace('query_memory: null,             // svc #0x06 wrapper',
      'query_memory: null,           // drifted comment');
    assert.throws(() => buildCarrier({shimSource: drifted, offsetsTable: offsetsFixture}),
      error => error.code === 'E_CARRIER_ANCHOR');
  });

  // A minimal fixture kit exercising the same JSON shapes as the real
  // civswitch-kit checkout (values are fixture-small, not the hardware ones).
  const fixtureKit = {
    functions: {
      svcQueryMemory: {offset: 100}, svcSendSyncRequest: {offset: 101}, svcCloseHandle: {offset: 102},
      memcpy: {offset: 200}, memmove: {offset: 201}, memset: {offset: 202}
    },
    threadCode: {
      functions: {longjmp: {offset: 300}, create: {offset: 301}, join: {offset: 302},
        exit: {offset: 303}, sleep: {offset: 304}},
      rawSvc: {
        functions: {createThread: {offset: 400}, startThread: {offset: 401}, exitThread: {offset: 402},
          waitSynchronization: {offset: 403}, getThreadPriority: {offset: 404}, getThreadCoreMask: {offset: 405}},
        managerList: {globalPointerOffset: 500}
      }
    },
    eventCode: {functions: {initialize: {offset: 600}, finalize: {offset: 601}, signal: {offset: 602},
      clear: {offset: 603}, wait: {offset: 604}}},
    timingCode: {functions: {frequency: {offset: 700}}},
    hashCode: {offset: 800},
    scheduling: {functions: {
      'pthread_setaffinity_np': {offset: 900}, 'pthread_getaffinity_np': {offset: 901},
      'nn::os::GetThreadAvailableCoreMask()': {offset: 902},
      'nn::os::GetCurrentCoreNumber()': {offset: 903},
      'nn::os::SetThreadCoreMask(nn::os::ThreadType*, int, unsigned long)': {offset: 904},
      'nn::os::GetThreadCoreMask(int*, unsigned long*, nn::os::ThreadType const*)': {offset: 905}}},
    layout: {mountTableOffset: 1000},
    proxy: {globalOffset: 1100, functionOffset: 1101},
    target: {sdkBytes: 6299648, pinningAllocationBytes: 6960, heapJitterBytes: 192, fieldCopies: 1,
      thread: {stackBytes: 81920}, hello: {sdkCrc32: 157086863},
      sessionManager: {stateOffset: 92, stateValue: 3}},
    template: JSON.parse(await fs.readFile(path.join(PROJECT, 'offsets/civ7-100.template.json'), 'utf8'))
  };

  await step('import: maps every kit table to our schema', async () => {
    const {table, report} = importKit(fixtureKit);
    assert.strictEqual(table.svc.query_memory, 100);
    assert.strictEqual(table.svc.create_thread, 400);
    assert.strictEqual(table.svc.exit_thread, 402);
    assert.strictEqual(table.svc.wait_synchronization, 403);
    assert.strictEqual(table.sdk_offsets.longjmp, 300);
    assert.strictEqual(table.sdk_offsets.thread_manager_global, 500);
    assert.strictEqual(table.sdk_offsets.event_wait, 604);
    assert.strictEqual(table.sdk_offsets.sha256, 800);
    assert.strictEqual(table.sdk_offsets.set_affinity, 900);
    assert.strictEqual(table.mounts.table_offset, 1000);
    assert.strictEqual(table.mounts.proxy_global, 1100);
    assert.strictEqual(table.modules.sdk.size, 6299648);
    assert.strictEqual(table.timing.sdk_frequency, 700);
    assert.strictEqual(table.timing.expected_frequency, 31250000);
    assert.ok(Object.keys(report.filled).length >= 30, 'a full table came across');
    assert.ok(report.imported.length >= Object.keys(report.filled).length,
      'every filled entry (plus composites) is in the import log');
    assert.ok(report.imported.every(line => / <- /.test(line)), 'every import names its source');
  });

  await step('import: jmp_buf decoded unmangled; TODO surface explicit', async () => {
    const {table, report} = importKit(fixtureKit);
    assert.strictEqual(table.jmp_buf.mangled, false);
    assert.strictEqual(table.jmp_buf.size, 0x90);
    assert.ok(table.jmp_buf.layout.includes('sp@0x60'));
    for (const key of ['modules.*.first_page_sha256', 'svc.connect_to_named_service',
      'timing.frequency_module_size', 'mounts.accessor_*'])
      assert.ok(report.todo[key], 'TODO for ' + key);
    assert.ok(table._civswitch.todo['svc.connect_to_named_service'].join(' ').includes('GetServiceHandle'),
      'TODO records the kit GetServiceHandle alternative');
  });

  await step('import: geometry block carries the Civ7-BC retune constants', async () => {
    const {table} = importKit(fixtureKit);
    const g = table._civswitchGeometry;
    assert.strictEqual(g.pinningAllocationBytes, 6960);
    assert.strictEqual(g.heapJitterBytes, 192);
    assert.strictEqual(g.fieldCopies, 1);
    assert.strictEqual(g.writeSize, 0x800000);
    assert.strictEqual(g.probeReadSize, 0x10000);
    assert.strictEqual(g.positiveFillSegment, 63);
    assert.strictEqual(g.waitTimeoutResult, 59905);
    assert.strictEqual(g.sdkCrc32, 157086863);
  });

  console.log('civ7js-carrier-test: ' + passed + ' scenarios passed');
}

main().then(() => process.exit(0), error => {console.error(String(error.message || error)); process.exit(1);});
