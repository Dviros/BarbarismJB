# CIVSWITCH-RUNBOOK — the day a Civ 7 1.0.0 process exists on the rig

Step-by-step delivery plan for the moment cart access (or unpatched digital
Civ 7 1.0.0) is available on our **fw 23.0.0** console: loader up → our engine
deployed through it → fs ARW → PID 1 → the `ns_ssversion:/entry` gate-clear
payload → the WifiWebAuthApplet opens on the rig (the WebKit host, which then
removes the cartridge from the critical path).

Companion documents: [`CIVSWITCH-INTEGRATION.md`](CIVSWITCH-INTEGRATION.md)
(the architecture, the kit citations, the offsets contract),
[`APPLET-GATE-RESEARCH.md`](APPLET-GATE-RESEARCH.md) (the gate + write
recipe), [`RIG.md`](RIG.md) (the network rig), [`SHELL.md`](SHELL.md).

Standing rules (they were true for the CN kit and they are true for us):

- **Never update past 23.0.1** (23.5.0 patches the fs bug; our console is
  23.0.0 — keep it there). 90DNS / the starved rig DNS on every network the
  console joins. Airplane mode when idle.
- **Civ 7 stays on Switch-1 cartridge 1.0.0.** Never accept an update.
- Everything is tethered and in-memory; a reboot undoes a run. A failed run
  may wedge the console — the kit's rule: hold POWER 12 s, wait 5 s, boot.
- **Recreate the throwaway save after any run that does not complete cleanly**
  (the kit measured a degraded save zeroing the overwrite win rate; a reboot
  does NOT reset it — `kit:docs/FINDINGS.md §3`).
- Expect ~20% per-wave / ~30% per-boot canary hit on a healthy save; 3–4
  attempts are normal. Watch the PC logs, not the game screen (their screens
  lie — "Executed successfully" prints even on failure).
- Don't touch the console while a run is in flight; wedge > 3 min = hard reset.
- Autosave settings: keep count 1 / every 25 turns (cannot be disabled).

## Phase 0 — once, before the cart is ever inserted (offline, do now)

1. `bash tests/run-all.sh` — full offline sweep, including the new
   `tests/civ7js-carrier-test.cjs` (loader client, carrier bake, offsets
   import, civshim ops 12–15 round-trips).
2. Seed the offsets table from the kit (already done — recorded here for
   reproducibility):
   `git clone https://gitee.com/mza1010/civswitch-kit /tmp/civswitch-kit && \
    node engine/carrier/civ7js/import-civswitch-offsets.cjs /tmp/civswitch-kit`
   → 38 hardware-validated values; the explicit M0 remainder is listed in
   `offsets/civ7-100.json` `_civswitch.todo` (first-page sha256 pins,
   `modules.main.size`, `svc.connect_to_named_service`, the `timing`
   second-module question, the `mounts` accessor constants, four gadgets).
3. Decide the loader-delivery method (Phase 2). Both are proven:
   - **Pico HID typing** (Gezine CivSwitch PicoSwitch / Element2424
     base): the XSS payload is typed into the chat box as a controller macro.
     One-time firmware flash; no second console needed.
   - **XSTRIG.Civ7Save persistent trigger** (the kit's default): one-time
     install via a Switch 1 homebrew NRO (`civswitch-ldn-nx`) over LDN —
     after that, every boot → Load Game re-arms the loader automatically.
     NOTE the kit's warning: the one-shot install **wipes all Civ 7 single
     player saves** (`kit:README.md §4`); back up first
     (`kit:save-tools/dump_save_tree.py`).
   - Manual chat-XSS typing via a USB keyboard is the zero-equipment fallback.
4. Prepare the rig network: wired ethernet to the PC if possible (the kit ran
   wired both ends; the fs race is timing-sensitive), starved DNS
   (`--dns-mode conntest` — NOT catchall; see APPLET-GATE-RESEARCH.md).

## Phase 1 — console prep (once per console state)

1. Confirm firmware 23.0.0 (Settings → System). Do NOT update.
2. Insert the Civ 7 Switch-1 cartridge. Boot the game past the title screen.
3. Create/keep a **sacrificial single-player save** with free space ≥
   `0x800000 + 0x400000 + 0x10000` (8 MiB write + 4 MiB margin + 64 KiB; the
   kit measured ≥ `0x3EA8000` free on a healthy save). Back it up if it
   matters.
4. Civ 7 settings: autosave count 1, interval 25 turns.

## Phase 2 — arm the loader (per boot)

The game's screen must end at `Awaiting payload at <S2-IP>:9026`:

- **XSTRIG route**: title screen → **Load Game** → `XSTRIG.Civ7Save` → load.
  (After any failed run, the kit's field protocol: run
  `restore_save.py <backup-dir> <S2-IP> 9026` while the loader is up, then
  **hard-reset (POWER 12 s) and Load Game again** before the next attempt.)
- **Pico route**: attach the Pico, trigger the chat-XSS macro, wait for the
  loader banner.
- **Manual route**: open the in-game chat (multiplayer screen), type/send the
  XSS payload, wait for the banner.

Do not probe :9026 with empty connections (3 bad connections → the loader
rebuilds its listener — `kit:README.md §8`). Our loader client never does.

## Phase 3 — deploy our engine through the loader

```sh
# M1 in one shot (deploy + transport check):
node run.cjs --deploy --check <S2-IP>
#   deploy: carrier built (offsets baked) -> pushed via :9026
#   expect the loader log line: "civshim: listening on :39381"
#   then: hello bases, PING/QUERY/ALLOC/WRITE+READ/CALL/FREE ok
#   -> "M1 transport check passed."

# M2 with the hardware-qualified thread path:
node run.cjs --check-workers 4 --worker rawsvc <S2-IP>
#   expect: THREAD_SCHED_BORROW ok (priority ~43, cores from the mask)
#           THREAD_CREATE_RAW x4 ok; svcWaitSynchronization poll joins clean
#           -> "M2 worker check passed."
```

Reading the results against the kit's hardware facts
(CIVSWITCH-INTEGRATION.md §2):

- The hello `sdk` base + `sdkSize` 0x602000 should match the kit's module map;
  `main`/`sdk` first-page pins verify once M0's dump fills them.
- If op 15 reports priority ≈ 43 and a non-trivial core mask — the manager
  list matches the kit's observed layout (their values: 43/44/59/28).
- If `svcCreateThread` rejects a core with 0xE001, the host automatically
  walks the borrowed mask; the kit observed core 2 working (mask 0x4).

## Phase 4 — close the M0 remainder (one dump session, crash-tolerant)

The table is already 38/`REQUIRED+worker` values deep; what is left:

1. `python3 tools/dump_recv.py --port 39390 --outdir dumps/run1` (host),
   edit `HOST_IP` in `payloads/dumper.js`, then deploy it through the loader:
   `node engine/carrier/civ7js/deploy.cjs <S2-IP>` after swapping the payload,
   or `python3 send_js.py <S2-IP> payloads/dumper.js` from a CivSwitch
   checkout. Collect both module dumps (cycles via the Phase 2 re-arm +
   hard-reset loop on a crash).
2. Offline: `tools/svc_scan.py` (the svc #0x1F wrapper for
   `svc.connect_to_named_service` — the one REQUIRED gap), first-page sha256
   pins + `modules.main.size` from the manifest, `tools/gadget_scan.py` for
   the four open gadget entries. Confirm `jmp_buf` in Ghidra (the kit-decoded
   unmangled x19–x30/sp/d8–d15 layout) and the `mounts` accessor constants.
3. Re-run the import (idempotent) or hand-edit `offsets/civ7-100.json`; then
   `offsets.load()` must pass clean (no REQUIRED warnings) — the pipeline
   gate opens.
4. Cross-check: the sdk text CRC-32 should equal the kit's 157086863 for this
   cartridge build (recorded in `_civswitchGeometry`).

## Phase 5 — the fs exploit (fresh boot per attempt)

```sh
node run.cjs --stage acquire --worker rawsvc <S2-IP>
node run.cjs --stage pid      --worker rawsvc <S2-IP>
node run.cjs --stage all      --worker rawsvc <S2-IP>   # launch + demo + dump
```

- Success lines: `FS execution verified. Original instructions restored and
  scratch cleaned up.` / `Restart the console when finished.`
- Failure: keep the `runs/civ-*` folder, read
  `switch2/acquisition.log` + `switch2/pipeline.json` + `reserved-gap-*.json`
  `error` fields, hard-reset, recreate the throwaway save if the run did not
  complete cleanly, retry.
- GEOMETRY: the Civ7 values are recorded in `offsets/civ7-100.json`
  `_civswitchGeometry` (pin cost 6960, jitter 192, fieldCopies 1,
  writeSize 0x800000, probeReadSize 0x10000, fill segment 63). If the
  23.0.0 fs differs from 23.0.1's, the loud row is `pinCostOk` — re-measure
  and adjust the probe knob before burning attempts (the analysis is in
  CIVSWITCH-INTEGRATION.md §2d).
- Firmware dump when stable: `node run.cjs --rpc --dump-firmware --worker rawsvc <S2-IP>`
  (the kit's reference result: 90/90 titles, 222 MB).

## Phase 6 — the applet gate clear (`ns_ssversion:/entry`)

Once Phase 5 leaves a held session (`--rpc` / `--shell`), clear the
safe-system-version gate that blocks WifiWebAuthApplet on our 23.0.0 console
(the full research: `APPLET-GATE-RESEARCH.md`). Gate is TRUE only while
`ns_ssversion:/entry`'s version word is GREATER than the installed
NCM-DB SystemUpdate meta — our console has a cached 23.0.1 entry while
running 23.0.0.

Through the shell (`python3 tools/shell_client.py <port>`) or a small
held-session script — system save `0x8000000000000049`, mounted
`ns_ssversion:/`:

1. **Pull** the live entry: open the system save (mac2jb's ns2-savekit READ
   path works unpatched: `save-pull-root.cjs --space 0 --type 0 --static-id
   8000000000000049`) and read `ns_ssversion:/entry` — expect
   `{u64 application-id, u32 version}` on the ContentMeta/CNMT scale, version
   > our installed meta (that is the gate being TRUE).
2. **Patch** the version word down to a value ≤ the installed 23.0.0 meta
   (e.g. the installed meta's own version). Leave the application-id intact.
3. **Write + Commit** — the write path is the ~10-line extension on the same
   savekit open (write `staticSaveDataId` at attribute +0x20, fsp-srv cmd 52
   `OpenSaveDataFileSystemBySystemSaveDataId`, whitelist the id).
4. **Reboot offline** (airplane mode first) — ns caches the check result; the
   reboot is the reliable flush. A failed bvc check does NOT poison the
   state (the bench ran NXDOMAIN'd with entry==installed = open).
5. Boot into the rig network → connection test → the applet should launch
   (gate FALSE) → the captive-portal rig takes over (`tools/webkit-rig/
   launch.py --mode router --auto-probe --conntest-profile redirect
   --dns-mode conntest`) — the WebKit host workstream (docs/WEBKIT-*.md)
   becomes live without the cartridge.

Sanity limits: do NOT touch any other system save; if the pull shows an
unexpected entry shape, stop and re-read the research doc before writing.

## Phase 7 — keep the cartridges out of the critical path

With the applet open: the WebKit entry (free, no game) is armed for every
future boot, and the Civ 7 route remains the fallback/offline path. Nothing
was installed; a reboot still undoes everything except the `ns_ssversion`
entry (which is exactly the intended, documented, reversible-by-maintenance-
mode change) — re-verify with a pull after reboot.

## Failure triage quick table

| symptom | meaning | action |
|---|---|---|
| loader connect refused | game crashed/closed | relaunch Civ 7, re-arm (Phase 2) |
| `bad connection` messages on the game screen | something probed :9026 | stop probing; the loader rebuilds after 3 |
| deploy marker never appears | payload died in eval | check loader log tail; hard reset; retry |
| op 15 fails "no borrowable scheduling" | manager list empty/shifted | reboot; if persistent, the sdk layout differs — re-derive from our dump |
| svcCreateThread 0xE001 on every core | priority invalid | confirm op 15's priority really applied (log shows it); reboot |
| `svcWaitSynchronization 0x…` other than 0/0xEA01 | handle state wrong | treat as console wedge: hard reset |
| canary 0 hits over ~10 positive waves | save degraded (or 23.0.0 fs geometry differs) | recreate the throwaway save; then check the `pinCostOk` row |
| `pinCostOk` false | 23.0.0 fs differs from the kit's 23.0.1 measurement | re-measure, adjust `pinningAllocationBytes` knob (documented in INTEGRATION §2d) |
| wedge > 3 min anywhere | console dead | POWER 12 s → 5 s → boot → Phase 2 |
