# Changelog

All notable changes to BarbarismJB are documented here. The version constant
lives in `engine/shared/version.cjs`; format follows Keep a Changelog.

## 0.1.0 — 2026-11-10

Initial release (developed under the working name `civ2jb`; see
PROVENANCE.md). Milestones M0–M2 built and verified offline; M3–M6 are
hardware-gated; M7 planned.

### Added
- M0 bootstrap: `payloads/dumper.js` (svc scan + QueryMemory map + zero-copy
  module dump over CIVDUMP1), `tools/dump_recv.py`, `tools/svc_scan.py`,
  `tools/gadget_scan.py` (all stdlib-only, all with `--self-test`),
  `offsets/civ7-100.template.json` + workflow documentation.
- M1 transport: `payloads/civshim.js` console-side bridge (11-op binary
  protocol on :39381, degraded mode before the offsets upload, self-healing
  listener) and the host stack in `engine/lib/` (`connection.cjs` CIV1
  client, `bridge.cjs` Civshim client + loopback HTTP front,
  `offsets.cjs` loader/validator).
- M2 workers: ropchain worker backend (`engine/shared/frames.cjs` `buildRop`,
  `engine/switch2/app/native-worker.cjs`) driving forged jmp_buf + ROP chains
  through THREAD_CREATE/THREAD_JOIN; legacy `frames` backend preserved.
- Engine port: ns2jb engine adapted to the Civ 7 host process — 80 files
  byte-identical to upstream, 12 adapted + 2 added, all marked
  `// barbarism:`; pending ports guarded by loud `unported()` failures.
- Host entry `run.cjs` with `--check` (M1) and `--check-workers N` (M2)
  verifications, `--stage` filtering, `--rpc`/`--dump-firmware` passthrough.
- Test suites: `tests/protocol-conformance.cjs` (real host stack vs fake
  console), `tests/civshim-sim.cjs` (real payload vs stubbed loader
  primitives over a SharedArrayBuffer channel), `tests/run-all.sh`.
- First-party infrastructure: `engine/shared/errors.cjs` (one error-code
  taxonomy), `engine/shared/log.cjs` (zero-dep leveled tagged logger),
  `engine/shared/version.cjs`, CHANGELOG, PROVENANCE, README.
- Frame-boundary hardening on both ends: exact payload lengths, span/size
  caps validated before any native call, UPD_OFFSETS payload cap, response
  length checks.

## Unreleased — final app-layer Civ 7 ports (M3/M4 unblock)

The seven SmileBASIC-pinned app modules are offsets-driven; no `unported()`
guard remains in the engine. Every module fails loudly (`E_OFFSETS`) naming
the exact `offsets/civ7-100.json` key it needs, so an M0 dump lights each
stage up without further code changes. Full key table: `offsets/README.md` §4.

### Changed
- `engine/switch2/app/events.cjs` — nn::os event wrappers from
  `sdk_offsets.event_initialize/signal/clear/finalize/wait`; `code` keeps the
  upstream sdk-relative shape (probe wait/signal, worker gates). The frames
  backend still byte-pins via `event-code.json` (re-fingerprint for Civ 7).
- `engine/switch2/app/timing.cjs` — tick source = `svc.get_system_tick`; the
  second-module true-frequency discovery (SmileBASIC SDK lied with 19.2 MHz;
  nnCompatThin held the real 31.25 MHz) became the `timing` offsets group.
  Runtime probe + validation preserved; optional SDK cross-check recorded.
- `engine/switch2/app/affinity.cjs` —
  `sdk_offsets.set_affinity/get_affinity/available_core_mask/current_core_number`;
  the nnCompatThin GOT walk is gone (no Civ 7 counterpart known); per-role
  core pinning keeps set + read-back verification.
- `engine/switch2/app/inspect-mounts.cjs` — mount-table walker driven by the
  `mounts` offsets group (table head, intrusive-list geometry, accessor/
  implementation/service/manager layout, borrowable names); mounts.json
  records the layout used. SmileBASIC verifiedFunctions identity is carried
  by the offsets-table module pins.
- `engine/switch2/app/mounted-save.cjs` — borrows the live `save:`/`tmp:`
  session via the ported layout + `mounts.proxy_global`; donor discipline
  (root-only paths, never `save:/saves/`) unchanged in `ro/files.cjs`.
- `engine/switch2/app/filesystem.cjs` — `nativeHash` uses optional
  `sdk_offsets.sha256`; while null it degrades to the readback-verify pattern
  (full read-back + host-side hash, mode recorded).
- `engine/switch2/ro/worker-control.cjs` — worker call lists offsets-driven:
  `send` → `svc.send_sync_request`; `app-service` →
  `svc.connect_to_named_service` (handle in x0); cancellation →
  `svc.cancel_synchronization` (Switch 2 `svc #0x19` — correcting the earlier
  0x53 guess; the wrapper's unique svc site is self-pinned at runtime and the
  `cancelCode` export is preserved for retained-memory); ropchain
  finished-probe = every result slot left SENTINEL.

### Added
- `engine/switch2/app/native-offsets.cjs` — fail-loud `E_OFFSETS` lookups for
  entries `lib/offsets.cjs` does not resolve (extra svc wrappers, `timing`,
  `mounts`), shared by the ported modules.
- Offsets schema: `sdk_offsets.event_*`, `get_affinity`, `available_core_mask`,
  `current_core_number`, `sha256`; new `timing` and `mounts` groups; the
  `svc.cancel_synchronization` note corrected to 0x19 (template + README).
- README: "Pending Civ 7 ports" became "Civ 7 ports status" — remaining
  SmileBASIC pins are now deliberate and listed (qualify's memcpy pin, the
  frames backend, ro/control's event-signal scan anchor).
