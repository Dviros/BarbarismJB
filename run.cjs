#!/usr/bin/env node
// run.cjs — BarbarismJB host entry.
//
// Purpose: connect to payloads/civshim.js (inside the Civ 7 process, TCP
// :39381 — the direction is inverted from ns2jb, whose SmileBASIC client
// connected in instead), cross-check the CIV1 hello against the offsets
// table and the module first-page sha256 pins, upload the console-consumed
// offsets (op 11), then either run a transport/worker verification
// (--check / --check-workers) or spawn the engine pipeline.
// Docs: README.md (quickstart + adaptation table), DESIGN.md.
// Exit codes: 0 success; 1 runtime failure (E_TIMEOUT, E_PROTOCOL, ...);
// 2 usage error (bad flags, missing console-IP).
// Logging: progress on stdout; diagnostics via shared/log.cjs (BARBARISM_LOG
// selects the level; warn/error go to stderr).
// Origin: ported from ns2jb run.cjs, heavily adapted for BarbarismJB —
// see `// barbarism:` markers.
//
// Usage: node run.cjs [options] console-IP
//   console-IP        the Switch 2's LAN IPv4 address (required)
//   --port N          civshim port (default 39381)
//   --stage NAME      acquire|pid|launch|demo|dump|all (default all) — stop
//                     cleanly after that milestone group for incremental tests
//   --rpc             hold the session open for rpc.cjs (full runs only)
//   --dump-firmware   also capture system code (needs --stage dump|all)
//   --shell[=PORT]    hold like --rpc and serve the BarbarismJB shell on
//                     loopback PORT (default: ephemeral, printed once);
//                     subsystems attach per stage progress, missing ones
//                     degrade to coded E_CONFIG errors (docs/SHELL.md)
//   --worker B        ropchain (default) | frames | rawsvc — worker backend
//                     (rawsvc = the civswitch-kit raw svcCreateThread path,
//                     the hardware-qualified mode for Civ 7 1.0.0)
//   --donor M         save (default) | tmp — donor/scratch mount source
//   --deploy          push the offsets-baked civshim carrier through the
//                     CivSwitch :9026 loader before connecting
//                     (engine/carrier/civ7js/; pair with --loader-port N)
//   --check           M1 transport verification: PING, QUERY, ALLOC, WRITE,
//                     READ-back, CALL (svcSleepThread 1ms) — then exit
//   --check-workers N M2 verification: N workers (default 4) running
//                     sleep+memcpy chains in parallel, joined and verified
//                     (--worker rawsvc exercises civshim ops 12-15)
//   --version         print the BarbarismJB version and exit
//
// DO NOT UPDATE THE CONSOLE PAST 23.0.1 (23.5.0 patches the fs bug).
const fs = require('node:fs/promises');
const {createWriteStream} = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const readline = require('node:readline');
const {connect} = require('./engine/lib/connection.cjs');
const offsets = require('./engine/lib/offsets.cjs');
const {serve} = require('./engine/lib/bridge.cjs');
const {VERSION} = require('./engine/shared/version.cjs');
const {createLog} = require('./engine/shared/log.cjs');
const {fail} = require('./engine/shared/errors.cjs');

const PROJECT = __dirname;
const CONSOLE_PORT = 39381;
const STAGES = ['acquire', 'pid', 'launch', 'demo', 'dump', 'all'];
const save = (file, value) => fs.writeFile(file, JSON.stringify(value, null, 2) + '\n', {mode: 0o600});
const DUMP_MARKER = '.barbarismjb-firmware-dump.json';
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const log = createLog('barbarism');

const USAGE = 'BarbarismJB ' + VERSION + '\n' +
  'Usage: node run.cjs [--port N] [--stage acquire|pid|launch|demo|dump|all]\n' +
  '  [--rpc] [--dump-firmware] [--worker ropchain|frames|rawsvc] [--donor save|tmp]\n' +
  '  [--deploy [--loader-port N]] [--check | --check-workers N] [--version] console-IP\n' +
  '\n' +
  '  Prerequisites: Civ 7 running with the CivSwitch :9026 loader armed. With\n' +
  '  --deploy the host pushes the offsets-baked civshim carrier through the\n' +
  '  loader itself (engine/carrier/civ7js/); without it, send payloads/civshim.js\n' +
  '  manually first (python3 send_js.py <ip> payloads/civshim.js).\n' +
  '  offsets/civ7-100.json must be filled in from the M0 bootstrap (seed it with\n' +
  '  engine/carrier/civ7js/import-civswitch-offsets.cjs — docs/CIVSWITCH-INTEGRATION.md).\n' +
  '  Switch 2 on firmware 23.0.1 only. Never update past 23.0.1.';

function parseArgs(args) {
  const options = {port: CONSOLE_PORT, stage: 'all', rpc: false, dumpFirmware: false,
    shell: false, shellPort: undefined,
    worker: 'ropchain', donor: 'save', check: false, checkWorkers: 0, host: null,
    deploy: false, loaderPort: 9026};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {options.help = true; continue;}
    if (arg === '--version' || arg === '-V') {options.version = true; continue;}
    if (arg === '--rpc') {options.rpc = true; continue;}
    if (arg === '--shell') {options.shell = true; continue;}
    if (arg.startsWith('--shell=')) {
      options.shell = true;
      const port = Number(arg.slice('--shell='.length));
      if (!Number.isInteger(port) || port < 1 || port > 65535)
        throw fail('E_USAGE', '--shell=PORT needs a valid TCP port');
      options.shellPort = port;
      continue;
    }
    if (arg === '--dump-firmware') {options.dumpFirmware = true; continue;}
    if (arg === '--check') {options.check = true; continue;}
    if (arg === '--check-workers') {
      const value = Number(args[++i]);
      if (!Number.isInteger(value) || value < 1 || value > 16) throw fail('E_USAGE', '--check-workers needs a count 1..16\n' + USAGE);
      options.checkWorkers = value;
      continue;
    }
    if (arg === '--stage') {
      const value = args[++i];
      if (!STAGES.includes(value)) throw fail('E_USAGE', '--stage must be one of ' + STAGES.join('|') + '\n' + USAGE);
      options.stage = value;
      continue;
    }
    if (arg === '--port') {
      const value = Number(args[++i]);
      if (!Number.isInteger(value) || value < 1024 || value > 65535) throw fail('E_USAGE', '--port must be 1024..65535');
      options.port = value;
      continue;
    }
    if (arg === '--worker') {
      const value = args[++i];
      if (!['ropchain', 'frames', 'rawsvc'].includes(value)) throw fail('E_USAGE', '--worker must be ropchain|frames|rawsvc');
      options.worker = value;
      continue;
    }
    if (arg === '--deploy') {options.deploy = true; continue;}
    if (arg === '--loader-port') {
      const value = Number(args[++i]);
      if (!Number.isInteger(value) || value < 1024 || value > 65535) throw fail('E_USAGE', '--loader-port must be 1024..65535');
      options.loaderPort = value;
      continue;
    }
    if (arg === '--donor') {
      const value = args[++i];
      if (!['save', 'tmp'].includes(value)) throw fail('E_USAGE', '--donor must be save|tmp');
      options.donor = value;
      continue;
    }
    if (net.isIPv4(arg) && !options.host) {options.host = arg; continue;}
    throw fail('E_USAGE', 'Unexpected argument: ' + arg + '\n' + USAGE);
  }
  if (!options.host) throw fail('E_USAGE', 'The console\u2019s IPv4 address is required\n' + USAGE);
  // barbarism: --shell rides the held-session lifecycle, so it implies --rpc.
  if (options.shell) options.rpc = true;
  if (options.rpc && options.stage !== 'all')
    throw fail('E_USAGE', '--rpc is only available on full runs (--stage all)');
  if (options.dumpFirmware && !['dump', 'all'].includes(options.stage))
    throw fail('E_USAGE', '--dump-firmware needs --stage dump (or the default all)');
  return options;
}

function preflightNode() {
  const [major] = process.versions.node.split('.').map(Number);
  if (major < 22)
    throw Error(`Node 22 or newer is required (running ${process.version}); the engine uses fs.cp/cpSync, fs.statfs, and readline/promises semantics validated on 22+`);
}

async function prepareDumpDirectory(root = path.join(PROJECT, 'dumps')) {
  const parent = path.dirname(root);
  const previous = await fs.lstat(root).catch(error => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (previous) {
    if (!previous.isDirectory() || previous.isSymbolicLink() ||
        previous.dev !== (await fs.stat(parent)).dev)
      throw Error('Refusing to clean a symlink, mount, or non-directory at ' + root);
    const marker = await fs.readFile(path.join(root, DUMP_MARKER), 'utf8').then(JSON.parse).catch(error => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (!marker || marker.kind !== 'barbarismjb-system-code-dump' || marker.version !== 1) {
      if ((await fs.readdir(root)).length)
        throw Error('Refusing to clean an unrecognized nonempty dumps directory: ' + root);
    }
    await fs.rm(root, {recursive: true});
  }
  await fs.mkdir(root, {mode: 0o700});
  await fs.writeFile(path.join(root, DUMP_MARKER), JSON.stringify({
    kind: 'barbarismjb-system-code-dump', version: 1, started: new Date().toISOString()
  }, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  return {root, cleaned: !!previous};
}

async function sourceDigest() {
  const names = ['run.cjs'];
  async function walk(folder) {
    for (const entry of await fs.readdir(path.join(PROJECT, folder), {withFileTypes: true})) {
      const name = folder + '/' + entry.name;
      if (entry.isDirectory()) await walk(name);
      else if (entry.isFile()) names.push(name);
      else throw Error('Unexpected runtime file: ' + name);
    }
  }
  await walk('engine');
  const entries = [];
  for (const name of names.sort()) entries.push([name,
    crypto.createHash('sha256').update(await fs.readFile(path.join(PROJECT, name))).digest('hex')]);
  return crypto.createHash('sha256').update(JSON.stringify(entries)).digest('hex');
}

async function startEngine(directory, dumpDirectory = null, held = false, stage) {
  const log = await fs.open(path.join(directory, 'run.log'), 'wx', 0o600);
  const output = createWriteStream(null, {fd: log.fd, autoClose: false});
  const child = spawn(process.execPath, [path.join(directory, 'switch2/pipeline.cjs'),
    ...(dumpDirectory ? ['--dump-firmware'] : []), ...(held ? ['--hold-rpc'] : [])],
    {cwd: directory, stdio: ['ignore', 'pipe', 'pipe', ...(held ? ['ipc'] : [])], windowsHide: true,
      env: {...process.env, BARBARISM_STAGE: stage,
        ...(dumpDirectory ? {NS2_FIRMWARE_DUMP_DIR: dumpDirectory} : {})}}); // barbarism: stage filter + civ port env
  child.stdout.pipe(output, {end: false});
  child.stderr.pipe(output, {end: false});
  const lines = readline.createInterface({input: child.stdout});
  lines.on('line', line => {
    if (/^[1-4]\/4 |^Firmware: |^BarbarismJB: /.test(line)) console.log(line);
  });
  let childError;
  child.once('error', error => {childError = error;});
  output.once('error', error => {childError = error; child.kill('SIGTERM');});
  const finished = new Promise(resolve => child.once('close', (code, signal) => resolve({code, signal})))
    .then(async outcome => {
    if (!output.destroyed)
      await new Promise((resolve, reject) => {output.once('error', reject); output.end(resolve);});
    await log.close();
    return {...outcome, error: childError};
  });
  const ready = held ? new Promise((resolve, reject) => {
    const message = value => {
      if (value?.type !== 'held-ready') return;
      child.removeListener('message', message);
      resolve(value);
    };
    child.on('message', message);
    finished.then(outcome => {
      child.removeListener('message', message);
      reject(outcome.error || Error('The FS endpoint exited before the held session was ready.'));
    }, reject);
  }) : null;
  let releaseSent = false;
  return {child, finished, ready,
    async release() {
      if (held && !releaseSent && child.connected) {
        releaseSent = true;
        child.send({type: 'release'});
      }
      return finished;
    }};
}

function checkEngine(outcome) {
  if (outcome.error) throw outcome.error;
  if (outcome.code !== 0)
    throw Error('The run stopped. Keep the runs folder and restart the console before trying again.');
}

function waitForRpcStop(connection, signals = process, engineFinished = null) {
  return new Promise(resolve => {
    const socket = connection.socket;
    let settled = false;
    const finish = reason => {
      if (settled) return;
      settled = true;
      signals.removeListener('SIGINT', interrupt);
      signals.removeListener('SIGTERM', terminate);
      socket.removeListener('close', disconnected);
      resolve(reason);
    };
    const interrupt = () => finish('SIGINT');
    const terminate = () => finish('SIGTERM');
    const disconnected = () => finish('disconnected');
    signals.once('SIGINT', interrupt);
    signals.once('SIGTERM', terminate);
    socket.once('close', disconnected);
    if (engineFinished) engineFinished.then(() => finish('engine-exited'), () => finish('engine-exited'));
    if (connection.error || socket.destroyed) finish('disconnected');
  });
}

// barbarism: M1 transport verification — PING, QUERY, ALLOC, WRITE, READ-back,
// CALL (svcSleepThread 1ms). Runs straight through the bridge's civshim client.
async function transportCheck(civshim, resolved) {
  const pong = await civshim.request(1, Buffer.from('BarbarismJB-m1'));
  if (!pong.equals(Buffer.from('BarbarismJB-m1'))) throw Error('PING echo differs');
  console.log('  PING ok');
  if (resolved.svc.query_memory) {
    const region = await civshim.query(resolved.svc.query_memory);
    if (!region.permissions || !(region.size > 0n)) throw Error('QUERY returned an empty region');
    console.log('  QUERY ok (sdk region: type ' + region.type + ', perm ' + region.permissions +
      ', size 0x' + region.size.toString(16) + ')');
  } else console.log('  QUERY unavailable (svc.query_memory null) — expected before M0 completes');
  const scratch = await civshim.alloc(0x1000);
  if (!(scratch > 0)) throw Error('ALLOC failed');
  console.log('  ALLOC ok (0x' + scratch.toString(16) + ')');
  const marker = crypto.randomBytes(0x1000);
  await civshim.write(scratch, marker);
  const readBack = await civshim.read(scratch, marker.length);
  if (!readBack.equals(marker)) throw Error('WRITE/READ round-trip differs');
  console.log('  WRITE + READ back ok (4096 random bytes)');
  if (resolved.svc.sleep_thread) {
    const started = process.hrtime.bigint();
    await civshim.sleep(1000000n); // 1 ms
    const elapsedNs = Number(process.hrtime.bigint() - started);
    if (elapsedNs < 900000) throw Error('SLEEP/CALL returned implausibly fast');
    console.log('  CALL ok (svcSleepThread 1ms took ' + (elapsedNs / 1e6).toFixed(2) + ' ms host-side)');
  } else console.log('  CALL(sleep) unavailable (svc.sleep_thread null) — expected before M0 completes');
  await civshim.free(scratch);
  console.log('  FREE ok');
  return true;
}

// barbarism: M2 worker verification — N ropchain workers, each running a
// sleep+memcpy chain twice, created in parallel, joined, results checked.
// With --worker rawsvc the same chains launch through the civswitch-kit raw
// svcCreateThread path (civshim ops 12-15) — the hardware-qualified mode for
// Civ 7 1.0.0, where pthread_create silently no-ops.
async function workerCheck(civshim, resolved, table, count, workerBackend = 'ropchain') {
  const {buildRop} = require('./engine/shared/frames.cjs');
  const {parseJmpBuf} = offsets;
  const jmpBuf = parseJmpBuf(table.jmp_buf);
  const gadgets = resolved.gadgets;
  const memcpy = Number(resolved.sdkFn.memcpy);
  const sleep = Number(resolved.svc.sleep_thread);
  const sdk = Number(resolved.sdk);
  if (!memcpy) throw Error('--check-workers needs sdk_offsets.memcpy');
  if (!sleep) throw Error('--check-workers needs svc.sleep_thread');
  const rawsvc = workerBackend === 'rawsvc';
  const RAW_STACK_BYTES = 0x14000; // civswitch-kit target.civ7.json thread.stackBytes
  let scheduling = null;
  if (rawsvc) {
    if (!Number(resolved.svc.exit_thread)) throw Error('rawsvc needs svc.exit_thread (svc #0x0A wrapper)');
    scheduling = await civshim.threadSchedBorrow();
    if (!(scheduling.priority > 0 && scheduling.priority < 64) || scheduling.coreMask === 0n)
      throw Error('THREAD_SCHED_BORROW returned an unusable scheduling (priority ' + scheduling.priority + ')');
    const cores = [];
    for (let bit = 0n; bit < 64n; bit++) if ((BigInt(scheduling.coreMask) >> bit) & 1n) cores.push(Number(bit));
    scheduling.cores = cores;
    console.log('  THREAD_SCHED_BORROW ok (priority ' + scheduling.priority + ', cores [' + cores + '], ' + scheduling.nodes + ' nodes)');
  }
  const pattern = crypto.randomBytes(64);
  const workers = [];
  for (let index = 0; index < count; index++) {
    const base = await civshim.alloc(0x8000);
    if (!(base > 0) || base % 4096) throw Error('worker ALLOC failed');
    const src = await civshim.alloc(64);
    await civshim.write(src, pattern);
    const calls = [
      {function: sleep, args: [2000000n, 0n, 0n, 0n], name: 'sleep'},
      {function: memcpy, args: [base + 0x4000 + index * 64, src, 64, 0], name: 'copy'},
      {function: sleep, args: [2000000n, 0n, 0n, 0n], name: 'sleep2'},
      {function: memcpy, args: [base + 0x4000 + index * 64 + 0x800, src, 64, 0], name: 'copy2'}
    ];
    const liveArg = {sdk, sdkSize: table.modules.sdk.size || 0x8000000, sdkFn: resolved.sdkFn};
    if (rawsvc) liveArg.workerExit = Number(resolved.svc.exit_thread);
    const {frame, proof} = buildRop(base, liveArg, calls, jmpBuf, gadgets);
    await civshim.write(base, frame);
    let stack = 0;
    if (rawsvc) {
      stack = await civshim.alloc(RAW_STACK_BYTES);
      if (!(stack > 0) || stack % 4096) throw Error('raw stack ALLOC failed');
    }
    workers.push({index, base, src, stack, calls, proof});
  }
  console.log('  built ' + workers.length + ' ' + workerBackend + ' workers (jmp_buf ' + table.jmp_buf.size + 'B, mangled=' + table.jmp_buf.mangled + ')');
  const created = [];
  for (const worker of workers) {
    if (rawsvc) {
      let handle = 0;
      for (const core of scheduling.cores) {
        const reply = await civshim.threadCreateRaw(worker.base, worker.stack + RAW_STACK_BYTES,
          scheduling.priority, core);
        if (reply.handle) {handle = reply.handle; break;}
        if (reply.createResult !== 0xe001)
          throw Error('svcCreateThread failed 0x' + reply.createResult.toString(16) + ' for worker ' + worker.index);
      }
      if (!(handle > 0)) throw Error('svcCreateThread rejected every borrowed core (worker ' + worker.index + ')');
      created.push({...worker, thread: handle});
    } else {
      const thread = await civshim.threadCreate(worker.base);
      if (!(thread > 0)) throw Error('THREAD_CREATE failed for worker ' + worker.index);
      created.push({...worker, thread});
    }
  }
  console.log(rawsvc ? '  THREAD_CREATE_RAW x' + created.length + ' ok; joining (svcWaitSynchronization poll)...'
                    : '  THREAD_CREATE x' + created.length + ' ok; joining...');
  for (const worker of created) {
    if (rawsvc) {
      const deadline = Date.now() + 30000;
      for (;;) {
        const wait = await civshim.threadWait(worker.thread, 0n);
        if (wait.result === 0) {if (wait.index !== 0) throw Error('wait signaled a different handle'); break;}
        if (wait.result !== 59905)
          throw Error('svcWaitSynchronization 0x' + wait.result.toString(16) + ' (worker ' + worker.index + ')');
        if (Date.now() > deadline) throw Error('raw worker ' + worker.index + ' did not terminate');
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      const closed = await civshim.threadClose(worker.thread);
      if (closed !== 0) throw Error('svcCloseHandle 0x' + closed.toString(16));
    } else {
      await civshim.threadJoin(worker.thread);
    }
    const raw = await civshim.read(worker.base + worker.proof.resultsOffset, worker.proof.resultOffsets.length * 8);
    const values = worker.proof.resultOffsets.map((_, i) => raw.readBigUInt64LE(i * 8));
    if (values.some(value => value === 0xfedcba9876543210n))
      throw Error('worker ' + worker.index + ' left an unset result slot');
    const copied = await civshim.read(worker.base + 0x4000 + worker.index * 64, 64);
    const copied2 = await civshim.read(worker.base + 0x4000 + worker.index * 64 + 0x800, 64);
    if (!copied.equals(pattern) || !copied2.equals(pattern))
      throw Error('worker ' + worker.index + ' memcpy output differs');
  }
  console.log('  join x' + created.length + ' ok; all sleep/memcpy results stored and verified');
  for (const worker of created) {
    await civshim.free(worker.base);
    await civshim.free(worker.src);
    if (worker.stack) await civshim.free(worker.stack);
  }
  return true;
}

async function main(args = process.argv.slice(2)) {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(USAGE);
    return;
  }
  if (args.includes('--version') || args.includes('-V')) {
    console.log(VERSION);
    return;
  }
  preflightNode();
  const options = parseArgs(args);
  // barbarism: config knobs travel to the pipeline children through the env.
  process.env.BARBARISM_WORKER = options.worker;
  process.env.BARBARISM_DONOR = options.donor;

  // The offsets table is a hard prerequisite for pipeline runs; the transport
  // checks (--check / --check-workers) may run pre-M0 with a degraded feature
  // set so the M1 milestone can be verified before RE completes.
  let table;
  try {
    table = offsets.load(PROJECT); // fails loudly on missing REQUIRED entries
  } catch (error) {
    if (!options.check && !options.checkWorkers && !options.deploy) throw error;
    log.warn('offsets table unusable — continuing in transport-check mode.');
    log.warn('  (' + String(error.message).split('\n')[0] + ')');
    log.warn('  QUERY / SLEEP / THREAD checks will report unavailable; PING/CALL/READ/WRITE/ALLOC still verify.');
    table = {table: {target: {}, modules: {}, svc: {}, sdk_offsets: {}, jmp_buf: {},
      gadgets: {}, pins: {}}, file: null, warnings: [], workerReady: false};
  }
  for (const warning of table.warnings) log.warn(warning.replace(/^offsets warning: /, ''));

  // barbarism: --deploy — push the offsets-baked civshim carrier through the
  // CivSwitch :9026 loader before connecting (engine/carrier/civ7js/). Deploying
  // alone exits after the shim's "listening" line; combine with --check /
  // --check-workers to deploy-and-verify in one command.
  if (options.deploy) {
    const {deployCarrier} = require('./engine/carrier/civ7js/deploy.cjs');
    const deployed = await deployCarrier({project: PROJECT, offsetsTable: table.table,
      host: options.host, loaderPort: options.loaderPort, shimPort: options.port,
      log: line => console.log('  deploy: ' + line)});
    if (!options.check && !options.checkWorkers) {
      console.log('Deployed ' + deployed.carrier + ' — civshim is listening on :' + options.port + '.');
      console.log('Continue with: node run.cjs --check ' + options.host);
      return {platform: 2, version: VERSION, deployed: deployed.carrier, verified: true,
        console: options.host, port: options.port};
    }
  }

  const workspace = path.join(PROJECT, 'runs');
  await fs.mkdir(workspace, {recursive: true, mode: 0o700});
  const directory = await fs.mkdtemp(path.join(workspace, 'civ-'));
  const result = {platform: 2, version: VERSION, sourceSha256: await sourceDigest(), started: new Date().toISOString(),
    console: options.host, port: options.port, stage: options.stage, verified: false};
  let dumpDirectory;
  if (options.dumpFirmware) {
    const space = await fs.statfs(workspace);
    if (BigInt(space.bavail) * BigInt(space.bsize) < 512n * 1024n * 1024n)
      throw Error('The optional system-code dump needs at least 512 MiB free on the computer before starting.');
    const prepared = await prepareDumpDirectory();
    dumpDirectory = prepared.root;
    if (prepared.cleaned) console.log('Previous system-code dump removed from ' + dumpDirectory);
    console.log('System-code dump folder: ' + dumpDirectory);
  }

  let connected, bridge, engine, failure, shellListener;
  try {
    console.log(`Connecting to civshim at ${options.host}:${options.port}...`);
    connected = await connect({host: options.host, port: options.port});
    const hello = connected.addresses;
    console.log('Connected. main 0x' + hello.main.toString(16) + ', sdk 0x' + hello.sdk.toString(16) +
      ', scratch 0x' + hello.scratch.toString(16));
    // Cross-check the hello against the offsets table (throws on any svc
    // disagreement) and resolve absolute entry points for the whole engine.
    const resolvedOffsets = offsets.resolve(table.table, hello);
    result.hello = {main: hello.main, sdk: hello.sdk, session: path.basename(directory)};
    bridge = await serve(connected);

    // barbarism: upload the console-consumed offset groups (op 11 UPD_OFFSETS).
    // civshim.js ships with an empty dict; M0 discovers the real values after
    // the shim first runs, so the host pushes them here every connect. The
    // console keeps them for the whole shim session; QUERY/SLEEP/THREAD_* go
    // live immediately after this succeeds.
    {
      // Trim to the groups/keys the console itself consumes (payloads/civshim.js)
      // so the console's merged dict stays exactly its documented shape.
      const CONSOLE_SVC = ['query_memory', 'connect_to_named_service', 'send_sync_request', 'sleep_thread',
        // barbarism: raw-svc thread surface (civshim ops 12-15; the civswitch-kit
        // hardware recipe — docs/CIVSWITCH-INTEGRATION.md §2c).
        'close_handle', 'wait_synchronization', 'create_thread', 'start_thread',
        'get_thread_priority', 'get_thread_core_mask'];
      const CONSOLE_SDK = ['longjmp', 'pthread_create', 'pthread_join', 'pthread_exit', 'memset', 'memcpy',
        'thread_manager_global'];
      const pick = (group, keys) => Object.fromEntries(keys.map(key => [key, group[key] ?? null]));
      const modules = {};
      for (const name of ['main', 'sdk'])
        if (table.table.modules[name]?.size) modules[name] = {size: table.table.modules[name].size};
      const merged = await bridge.civshim.updateOffsets({svc: pick(table.table.svc, CONSOLE_SVC),
        sdk_offsets: pick(table.table.sdk_offsets, CONSOLE_SDK),
        ...(Object.keys(modules).length ? {modules} : {})});
      const liveCount = Object.entries(merged?.svc || {}).filter(([, value]) => value !== null).length;
      console.log('  console offsets uploaded (svc entries live: ' + liveCount + ')');
    }

    // barbarism: module pins replace the SmileBASIC SDK CRC (3925528160): each
    // pinned first page is read and hashed; a pin that exists must match.
    for (const [name, base] of [['main', hello.main], ['sdk', hello.sdk]]) {
      const pin = table.table.modules[name].first_page_sha256;
      if (!pin) {
        log.warn('no first_page_sha256 pin for the ' + name + ' module — skipping (fill it after M0)');
        continue;
      }
      const page = await bridge.civshim.read(base, 0x1000);
      if (hash(page) !== pin)
        throw Error('The ' + name + ' module first page does not match its pin — wrong game build or stale offsets table');
      console.log('  ' + name + ' first-page pin ok');
    }

    if (options.check) {
      await transportCheck(bridge.civshim, resolvedOffsets);
      result.checked = true;
      result.verified = true;
      console.log('M1 transport check passed.');
      return result;
    }
    if (options.checkWorkers) {
      await workerCheck(bridge.civshim, resolvedOffsets, table.table, options.checkWorkers, options.worker);
      result.workerCheck = {workers: options.checkWorkers};
      result.verified = true;
      console.log('M2 worker check passed.');
      return result;
    }

    // Session hand-off for the pipeline children: connection.json carries the
    // loopback bridge port plus the resolved absolute addresses (svc wrappers,
    // sdk functions, gadgets) and the raw offsets dict.
    const addresses = {...hello, svc: resolvedOffsets.svc, sdkFn: resolvedOffsets.sdkFn,
      gadgets: resolvedOffsets.gadgets, offsets: table.table, session: path.basename(directory)};
    await save(path.join(directory, 'connection.json'), {port: bridge.port, addresses});
    // barbarism: 'lib' is copied too — switch2/app/native-worker.cjs requires
    // lib/offsets.cjs (jmp_buf parsing) inside the spawned pipeline child.
    for (const name of ['lib', 'shared', 'switch2'])
      await fs.cp(path.join(PROJECT, 'engine', name), path.join(directory, name), {recursive: true});

    engine = await startEngine(directory, dumpDirectory, options.rpc, options.stage);
    if (options.rpc) await engine.ready;
    else checkEngine(await engine.finished);

    if (options.stage === 'all') {
      result.fs = JSON.parse(await fs.readFile(path.join(directory, 'switch2/fs-execution-current.json')));
      if (!result.fs.verified || !result.fs.restored ||
          (options.rpc ? !result.fs.retainedEndpoint?.ready || !result.fs.cleanup?.deferred :
            !result.fs.cleanup?.cleanedUp))
        throw Error('FS execution, restoration, or endpoint state did not verify.');
    } else {
      const pipeline = JSON.parse(await fs.readFile(path.join(directory, 'switch2/pipeline.json')));
      if (!pipeline.stoppedEarly) throw Error('The filtered run did not record its early stop');
      result.stoppedEarly = pipeline.stoppedEarly;
      console.log('Stopped after the ' + pipeline.stoppedEarly.after + ' group as requested (--stage ' + options.stage + ').');
    }
    if (options.dumpFirmware) {
      result.firmwareDump = JSON.parse(await fs.readFile(path.join(dumpDirectory, 'firmware-dump.json')));
      if (!result.firmwareDump.complete || result.firmwareDump.entries.length !== result.firmwareDump.inventory.total)
        throw Error('The system-code dump did not finish.');
    }
    result.verified = true;
    if (options.rpc) {
      result.rpc = {mode: 'held', state: 'listening', opened: new Date().toISOString()};
      await save(path.join(directory, 'result.json'), result);
      console.log('4/4 verified. Held RPC and FS memory endpoint remain live while this process and the game stay open.');
      console.log('Run folder: ' + directory);
      console.log('Check it locally: node rpc.cjs ' + directory + ' status  (from the ns2jb checkout)');
      if (options.shell) {
        // barbarism: mount the shell (docs/SHELL.md §4). Subsystems attach
        // lazily per stage progress; anything not up degrades to E_CONFIG.
        const {Shell} = require('./engine/lib/shell.cjs');
        const {serve: serveShell} = require('./engine/lib/shell-server.cjs');
        let fsEndpoint = null, roClient = null;
        try {fsEndpoint = await require(path.join(directory, 'switch2/tools/fs-memory.cjs')).connect();}
        catch (error) {console.log('shell: fs endpoint not attached (' + String(error.message).split('\n')[0] + '); fs/BIS commands stay disabled.');}
        try {
          const {Client} = require(path.join(directory, 'switch2/process/client.cjs'));
          roClient = await new Client().open();
        } catch (error) {console.log('shell: ro client not attached (' + String(error.message).split('\n')[0] + '); proc-* commands stay disabled.');}
        shellListener = await serveShell(
          new Shell(bridge.civshim, fsEndpoint, roClient, line => console.log('shell: ' + line)),
          {port: options.shellPort});
        result.shell = {port: shellListener.port, state: 'listening', opened: new Date().toISOString()};
        console.log('Shell listening on 127.0.0.1:' + shellListener.port +
          '  —  connect: python3 tools/shell_client.py ' + shellListener.port);
      }
      console.log('Stop with Ctrl-C; do not close Civ 7 until finished.');
      const reason = await waitForRpcStop(connected.connection, process, engine.finished);
      result.rpc = {...result.rpc, state: 'closed', reason, closed: new Date().toISOString()};
      if (reason === 'engine-exited') throw Error('The held FS endpoint exited unexpectedly.');
      checkEngine(await engine.release());
      result.fs = JSON.parse(await fs.readFile(path.join(directory, 'switch2/fs-execution-current.json')));
      if (!result.fs.cleanup?.cleanedUp) throw Error('Held FS resources did not clean up.');
      if (reason === 'disconnected') throw Error('Held RPC disconnected; do not replay an uncertain native request.');
    }
  } catch (error) {
    if (error.message === 'The FS endpoint exited before the held session was ready.') {
      try {
        const pipeline = JSON.parse(await fs.readFile(path.join(directory, 'switch2/pipeline.json')));
        if (pipeline.error) error = Error(pipeline.error.split('\n')[0]);
      } catch { /* The run log remains available if no pipeline report exists. */ }
    }
    result.error = error.message; failure = error;
  }
  finally {
    if (engine && options.rpc) {
      try {checkEngine(await engine.release());}
      catch (error) {(result.cleanupErrors ||= []).push({name: 'FS endpoint', error: error.message}); failure ||= error;}
    }
    try {await bridge?.close();}
    catch (error) {(result.cleanupErrors ||= []).push({name: 'bridge', error: error.message}); failure ||= error;}
    try {await shellListener?.close();}
    catch (error) {(result.cleanupErrors ||= []).push({name: 'shell', error: error.message});}
    if (shellListener && result.shell) result.shell.state = 'closed';
    result.completed = new Date().toISOString();
    await save(path.join(directory, 'result.json'), result);
  }
  if (failure) throw Error(explainFailure(failure.message) + '\nDetails: ' + directory);
  console.log('FS execution verified. Original instructions restored and scratch cleaned up.');
  if (options.dumpFirmware) console.log('System-program CodeFS dump: ' +
    path.join(dumpDirectory, 'firmware-dump.json'));
  console.log('Restart the console when finished.');
  return result;
}

// Upstream's tracker names these failures, and they are timing races rather
// than broken installs (docs/UPSTREAM-ISSUES.md in the ns2jb repo). The fs-side
// behavior is unchanged by the Civ 7 port, so the guidance carries over.
const KNOWN_FAILURES = [
  {match: 'Pinning storage was not created while the canary was pending',
    hint: 'The first wave lost the canary timing race, so the pin had nothing pending to\n' +
      'overlap. This is the race described in upstream issue #1. The engine cleaned up\n' +
      'after itself; restart the console and run again.'},
  {match: 'Overwrite missed the qualified canary',
    hint: 'The memory window qualified, but the overwrite did not land on the canary\n' +
      '(upstream issue #5). The engine kept its resources on purpose. Restart the\n' +
      'console and do not replay commands from the old session.'},
  {match: 'Repeated overwrite missed the canary',
    hint: 'The second overwrite missed the canary the first one had hit (upstream #1/#5).\n' +
      'The engine kept its resources on purpose. Restart the console and do not replay\n' +
      'commands from the old session.'},
  {match: 'FS acquisition did not complete',
    hint: 'Stage 2/4 never qualified, which is the timing race in upstream issue #1.\n' +
      'Restart the console and try again. With the Civ 7 client expect a lower\n' +
      'first-attempt rate (DESIGN.md section 9.2) — the wave retries, but geometry\n' +
      're-validation may be needed (README.md).'}
];

function explainFailure(message) {
  const known = KNOWN_FAILURES.find(entry => message.includes(entry.match));
  return known ? message + '\n\n' + known.hint : message;
}

module.exports = {main, parseArgs, explainFailure, sourceDigest, prepareDumpDirectory,
  startEngine, checkEngine, waitForRpcStop, transportCheck, workerCheck};
if (require.main === module) main().catch(error => {
  console.error(error.message);
  process.exitCode = error.code === 'E_USAGE' ? 2 : 1;
});
