// engine/carrier/civ7js/deploy.cjs — one-shot carrier deployment through the
// CivSwitch :9026 loader: bake offsets/civ7-100.json into payloads/civshim.js,
// push the carrier, and wait for the shim's "listening" log line.
//
// This replaces the kit's manual flow (kit:docs/RUNBOOK-P4.md §3: start the
// engine first, then `send_js.py <S2_IP> port/civ_bridge.js`) with a single
// host-side step that works both standalone and inside `run.cjs --deploy`:
//
//   node engine/carrier/civ7js/deploy.cjs <console-ip>
//   node run.cjs --deploy --check <console-ip>     # deploy + M1 in one shot
//
// Origin: original — BarbarismJB (glue; the loader wire behavior and the
// civshim payload are documented elsewhere in this repo).
// Docs: docs/CIVSWITCH-INTEGRATION.md §5, docs/CIVSWITCH-RUNBOOK.md.
'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const {buildCarrier, SHIM_RELATIVE} = require('./build-carrier.cjs');
const {sendAndAwait} = require('./loader-client.cjs');

const LISTEN_MARKER = port => 'civshim: listening on :' + port;

// Deploy and wait for the shim listener. `offsetsTable` may be the degraded
// empty table (pre-M0) — the carrier then boots degraded and the host's op-11
// upload on the next connect still lights the console features up.
async function deployCarrier({project, offsetsTable, host, loaderPort = 9026, shimPort = 39381,
    log = () => {}, connectTimeoutMs}) {
  const shimSource = await fs.readFile(path.join(project, SHIM_RELATIVE), 'utf8');
  const built = buildCarrier({shimSource, offsetsTable, shimPort});
  const carrierPath = path.join(project, 'runs', 'carrier-' + new Date().toISOString()
    .replace(/[:.]/g, '-').replace('T', 'T').slice(0, 19) + '.js');
  await fs.mkdir(path.dirname(carrierPath), {recursive: true});
  await fs.writeFile(carrierPath, built.carrier, {mode: 0o600});
  log('carrier built (' + built.carrier.length + ' B, svc ' + built.filled.svc + '/10, sdk ' +
    built.filled.sdk_offsets + '/5) -> ' + carrierPath);
  const marker = LISTEN_MARKER(shimPort);
  const result = await sendAndAwait({
    host, port: loaderPort, payload: built.carrier, connectTimeoutMs,
    markers: [marker], log: text => log(text.trimEnd())
  });
  log('shim is up: "' + result.marker.trim() + '"');
  return {carrier: carrierPath, digest: built.digest, marker: result.marker};
}

// CLI: node deploy.cjs [--loader-port N] [--port N] <console-ip> [project-root]
async function main(argv = process.argv.slice(2)) {
  const args = [...argv];
  let loaderPort = 9026, shimPort = 39381, host = null, project = process.cwd();
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--loader-port') loaderPort = Number(args[++i]);
    else if (args[i] === '--port') shimPort = Number(args[++i]);
    else if (!host && /^[0-9.]+$/.test(args[i])) host = args[i];
    else project = path.resolve(args[i]);
  }
  if (!host) {console.error('usage: node deploy.cjs [--loader-port N] [--port N] <console-ip> [project-root]'); process.exit(2);}
  let offsetsTable = {svc: {}, sdk_offsets: {}};
  try {offsetsTable = JSON.parse(await fs.readFile(path.join(project, 'offsets', 'civ7-100.json'), 'utf8'));}
  catch {console.error('note: no offsets/civ7-100.json — deploying the degraded (null-offsets) carrier');}
  const deployed = await deployCarrier({project, offsetsTable, host, loaderPort, shimPort,
    log: line => console.log('  ' + line)});
  console.log('Deployed ' + deployed.carrier);
  console.log('civshim listening on :' + shimPort + ' — connect with: node run.cjs --check ' + host);
}

module.exports = {deployCarrier};

if (require.main === module) main().catch(error => {console.error(String(error.message || error)); process.exit(1);});
