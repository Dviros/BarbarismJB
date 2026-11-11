// Read the application's existing mount objects; never unmount or close them.
// barbarism: PORTED to the offsets table (was: SmileBASIC sdk-layout.json —
// mountTableOffset 0xD1C8A0 plus four verifiedFunctions instruction pins —
// behind a loud unported() guard). The mount-table head and every accessor/
// implementation/service/manager layout constant now live in the `mounts`
// group of offsets/civ7-100.json, null until M0 RE maps Civ 7's nnSdk nn::fs
// mount structures (the template _notes carry the SmileBASIC reference values
// the upstream walker hardware-proved). The verifiedFunctions identity role is
// carried by the offsets table's module pins (modules.*.first_page_sha256 +
// pins.region_hashes). mounted-save.cjs borrows the same layout() and this
// walker's mounts.json; the donor/scratch strategy (README.md "Engine
// adaptation points") depends on both.
const fs = require('node:fs/promises');
const {client} = require('./rpc.cjs');
const {live, check} = require("./session.cjs");
const nativeOffsets = require('./native-offsets.cjs');
const pointer = (bytes, at = 0) => Number(bytes.readBigUInt64LE(at));

// barbarism: layout constants from offsets.json `mounts.*`. Every entry is
// M0 RE output (fail-loud E_OFFSETS naming the key when null). Reference
// values from the SmileBASIC capture: table_offset 13748384 (0xD1C8A0);
// intrusive-list geometry head_first 8 / accessor_backlink 8 / accessor_next
// 16; accessor name field at +24 (16 bytes) and implementation pointer at
// +40; implementation service pointer at +16; service vtable @0, manager @16,
// object id u32 @24; manager state u32@8 === 0x800, u32@0x5c === 3, slots
// pointer @16; filesystem-proxy global at 13748448 (0xD1C900) with the
// initialized flag byte at +8.
function layout() {
  if (!layout.cached) {
    layout.cached = Object.freeze({
      tableOffset: nativeOffsets.number(live, 'mounts.table_offset'),
      headFirst: nativeOffsets.number(live, 'mounts.head_first'),
      accessorBacklink: nativeOffsets.number(live, 'mounts.accessor_backlink'),
      accessorName: nativeOffsets.number(live, 'mounts.accessor_name'),
      accessorNameBytes: nativeOffsets.number(live, 'mounts.accessor_name_bytes'),
      accessorImplementation: nativeOffsets.number(live, 'mounts.accessor_implementation'),
      accessorNext: nativeOffsets.number(live, 'mounts.accessor_next'),
      implementationService: nativeOffsets.number(live, 'mounts.implementation_service'),
      serviceVtable: nativeOffsets.number(live, 'mounts.service_vtable'),
      serviceManager: nativeOffsets.number(live, 'mounts.service_manager'),
      serviceObjectId: nativeOffsets.number(live, 'mounts.service_object_id'),
      managerMagicOffset: nativeOffsets.number(live, 'mounts.manager_magic_offset'),
      managerMagicValue: nativeOffsets.number(live, 'mounts.manager_magic_value'),
      managerStateOffset: nativeOffsets.number(live, 'mounts.manager_state_offset'),
      managerStateValue: nativeOffsets.number(live, 'mounts.manager_state_value'),
      managerSlots: nativeOffsets.number(live, 'mounts.manager_slots'),
      proxyGlobal: nativeOffsets.number(live, 'mounts.proxy_global'),
      proxyInitFlagOffset: nativeOffsets.number(live, 'mounts.proxy_init_flag_offset'),
      names: Object.freeze([...nativeOffsets.list(live, 'mounts.names')])
    });
  }
  return layout.cached;
}

async function inspect() {
  const rpc = await client();
  const walk = layout();
  const head = live.sdk + walk.tableOffset;
  let next = pointer(await rpc.read(head + walk.headFirst, 8));
  const mounts = [], seen = new Set();
  while (next !== head) {
    check(next > 0 && next < 2 ** 39 && !seen.has(next) && seen.size < 32, 'Invalid mount list');
    seen.add(next);
    const accessor = next - walk.accessorBacklink;
    const bytes = await rpc.read(accessor, 128);
    const name = bytes.subarray(walk.accessorName, walk.accessorName + walk.accessorNameBytes)
      .toString('utf8').split('\0')[0];
    const implementation = pointer(bytes, walk.accessorImplementation);
    const implementationBytes = await rpc.read(implementation, 96);
    const service = pointer(implementationBytes, walk.implementationService);
    const entry = {name, accessor, implementation, service, accessorHex: bytes.toString('hex'),
      implementationHex: implementationBytes.toString('hex')};
    if (walk.names.includes(name)) {
      const serviceBytes = await rpc.read(service, 128);
      entry.serviceHex = serviceBytes.toString('hex');
      entry.serviceVtable = pointer(serviceBytes, walk.serviceVtable);
      entry.serviceVtableHex = (await rpc.read(entry.serviceVtable, 0xa0)).toString('hex');
    }
    mounts.push(entry);
    console.log(JSON.stringify({name, accessor, implementation, service}));
    next = pointer(bytes, walk.accessorNext);
  }
  await fs.writeFile(__dirname + '/mounts.json',
    JSON.stringify({session: live.session, at: new Date().toISOString(),
      layout: {...walk}, mounts}, null, 2) + '\n', {mode: 0o600});
}

module.exports = {inspect, layout};
if (require.main === module) inspect().catch(error => {console.error(error.message); process.exitCode = 1;});
