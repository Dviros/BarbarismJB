// Copy an existing application filesystem; never close its borrowed session.
// barbarism: PORTED to the offsets table (was: SmileBASIC sdk-layout.json +
// sdk-proxy-code.json pins behind a loud unported() guard). The mount walk and
// the accessor/implementation/service/manager layout come from the `mounts`
// offsets group via app/inspect-mounts.cjs layout(); the SDK filesystem-proxy
// service global is mounts.proxy_global with its initialized flag byte at
// mounts.proxy_init_flag_offset (SmileBASIC reference: global sdk+0xD1C900,
// 64 bytes past the mount table; flag byte at +8, bit 0). The
// verifiedFunctions live-SDK re-check is carried by the offsets table's module
// pins instead. BarbarismJB donor discipline (enforced in ro/files.cjs): with
// the default save donor the engine writes ONLY /main and /main.npdm at the
// save ROOT — never inside save:/saves/ where the XSTRIG.Civ7Save boot trigger
// lives — and removes them again in donor-cleanup.
const {live, check, u32} = require("./session.cjs");
const domain = require("./domain.cjs");
const {layout} = require("./inspect-mounts.cjs");

async function inspectMountedFilesystem(s, name = 'save') {
  const walk = layout();
  check(walk.names.includes(name),
    'Only the inspected application mounts are supported: ' + walk.names.join(', '));
  const captured = require("./mounts.json");
  check(captured.session === live.session, 'Save mount inspection belongs to another boot');
  const mount = captured.mounts.find(m => m.name === name);
  check(mount, 'Save mount was not inspected');
  const accessor = await s.read(mount.accessor, 128);
  check(accessor.subarray(walk.accessorName, walk.accessorName + walk.accessorNameBytes)
      .toString('utf8').split('\0')[0] === name &&
    Number(accessor.readBigUInt64LE(walk.accessorImplementation)) === mount.implementation,
    'Save mount changed');
  const implementation = await s.read(mount.implementation, 24);
  check(Number(implementation.readBigUInt64LE(walk.implementationService)) === mount.service,
    'Save service changed');
  const service = await s.read(mount.service, 32);
  check(Number(service.readBigUInt64LE(walk.serviceVtable)) === mount.serviceVtable,
    'Save service type changed');
  const manager = Number(service.readBigUInt64LE(walk.serviceManager)),
    objectId = service.readUInt32LE(walk.serviceObjectId);
  const state = await s.read(manager, 0x80);
  check(state.readUInt32LE(walk.managerMagicOffset) === walk.managerMagicValue &&
    state.readUInt32LE(walk.managerStateOffset) === walk.managerStateValue,
    'Unexpected SDK session manager');
  const slots = Number(state.readBigUInt64LE(walk.managerSlots));
  const borrowed = (await s.read(slots, 4)).readUInt32LE();
  check(borrowed > 0 && borrowed < 0xffff8000 && objectId > 0, 'Invalid borrowed save session');
  return {name, borrowed, objectId, manager};
}

async function cloneMountedFilesystem(s, name = 'save') {
  const {borrowed, objectId} = await inspectMountedFilesystem(s, name);
  const reply = await domain.send(s, 'Copy existing save filesystem', borrowed, domain.wire.control(1, u32(objectId)));
  const handle = domain.oneHandle(reply);
  await s.record({operation: 'MountedFilesystemCopied', name, borrowed, objectId, handle});
  return handle;
}

async function cloneMountedRoot(s) {
  const walk = layout();
  const mount = await inspectMountedFilesystem(s, 'save');
  const global = await s.read(live.sdk + walk.proxyGlobal, Math.max(16, walk.proxyInitFlagOffset + 1));
  check(global[walk.proxyInitFlagOffset] & 1, 'SDK filesystem proxy is not initialized');
  const service = Number(global.readBigUInt64LE());
  const object = await s.read(service, 32), root = object.readUInt32LE(walk.serviceObjectId);
  check(Number(object.readBigUInt64LE(walk.serviceManager)) === mount.manager && root > 0 && root !== mount.objectId,
    'SDK root and save do not share the expected domain');
  const handle = domain.oneHandle(await domain.send(s, 'Clone SDK filesystem domain', mount.borrowed, domain.wire.control(2)));
  return {owner: {label: 'Owned clone of SDK filesystem domain', handle, root}, filesystemId: mount.objectId};
}

module.exports = {cloneMountedSave: s => cloneMountedFilesystem(s, 'save'), cloneMountedFilesystem, cloneMountedRoot};
