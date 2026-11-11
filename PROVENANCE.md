# Provenance

BarbarismJB is a **derived research work**. It contains no code written from
scratch in a vacuum: the engine is a port of someone else's jailbreak, the
console entry point rides someone else's game exploit, and even that exploit's
core traces to a third party. This file records the full derivation tree and
the licensing truth, honestly, because the honest answer is "mixed and partly
unlicensed."

**This project is for research on hardware you own. Nothing here is licensed
for proprietary redistribution.**

## Derivation tree

```
Nintendo Switch 2 system software (firmware 23.0.1)
└── ns2jb  —  pepsipu  (https://gitlab.com/pepsipu/ns2jb)
    │         fs sysmodule exploit + host-driven engine (SmileBASIC host).
    │         NO LICENSE FILE PUBLISHED. Upstream README, verbatim intent:
    │         "This is research code; the copyright stays with the authors
    │          above. Treat it as something to study and run on your own
    │          hardware, not something to redistribute as your own."
    │         Research-only terms per its README; it is explicitly not a
    │         CFW/piracy tool ("does not install custom firmware or
    │         persistence").
    └── ns2jb fork  —  kurumuz  (https://gitlab.com/kurumuz/ns2jb)
        │         memory-layout adaptation, bounded retries, longer timeouts,
        │         held RPC, firmware dump, five-argument bootstrap. Same
        │         no-license status; the copy in ../repos/ns2jb ships this
        │         fork by default and carries the same research-only terms.
        └── BarbarismJB engine/   ← 80 of 101 files BYTE-IDENTICAL to that
            │                        fork; 12 adapted + 2 added (marked
            │                        `// barbarism:`); first-party additions:
            │                        shared/errors.cjs, shared/log.cjs,
            │                        shared/version.cjs, tests/, the tools'
            │                        hardening. The ns2jb stage pipeline,
            │                        wave geometry, IPC framing, donor-FS and
            │                        firmware-dump logic are reused, not
            │                        reimplemented.
            │
Civilization 7 (Switch-1 cartridge 1.0.0)
└── Netflix-N-Hack / inject.js  —  NetflixNHack
    │   (https://github.com/NetflixNHack/Netflix-N-Hack) — **GPL-3.0**
    │   The V8 exploitation core (CVE-2021-38003 TheHole → addrof/fakeobj →
    │   fake BigUint64Array → arbitrary 64-bit R/W).
    ├── fork: ufm42 / Netflix-N-Hack — inject.js
    │   (https://github.com/ufm42/Netflix-N-Hack/blob/main/inject.js)
    └── CivSwitch core.js  —  Gezine  (**MIT**, LICENSE in ../repos/CivSwitch)
        │   Civ 7 chat-XSS toolchain. core.js references the Netflix-N-Hack
        │   inject.js exploit core (stated in its own README credits) and
        │   builds call_rop, malloc/free, nn::socket ROP helpers, and the
        │   :9026 eval-in-closure JS loader on top. MIT covers Gezine's
        │   contributions; the referenced exploit core keeps its GPL-3.0
        │   lineage.
        └── BarbarismJB payloads/  ← payloads/civshim.js and payloads/
                                 dumper.js are eval'd INSIDE the CivSwitch
                                 loader closure and call those GPL-lineage
                                 primitives by name. They are original code
                                 for this project, but they are not
                                 license-isolated from what they run against
                                 and link to at runtime.
            └── civswitch-kit  —  mza1010 (https://gitee.com/mza1010/civswitch-kit)
                │         **GPL-2.0** (whole package). The public CN kit that
                │         proved the Civ 7 1.0.0 → fs exploit → firmware-dump
                │         chain end-to-end (RUN 38, dump 90/90). It contains
                │         the slapah/CivSwitch fork's ns2jb-port layer
                │         (baseline commit 7d422e52; the fork itself is not
                │         publicly fetchable) plus 8 documented patches.
                └── BarbarismJB 2026-11-11 integration  ← three inputs:
                         (1) **Offset values and hardware facts** (svc wrapper
                             offsets, thread-manager layout, jmp_buf shape,
                             Civ7-BC fs geometry constants) imported into
                             offsets/civ7-100.json by engine/carrier/civ7js/
                             import-civswitch-offsets.cjs — every leaf carries
                             its kit source in the file's `_civswitch` block.
                         (2) **Design-derived code**: civshim ops 12-15
                             (raw svcCreateThread/StartThread/WaitSynchronization/
                             CloseHandle + the manager-list scheduling borrow)
                             and the `rawsvc` worker backend implement the
                             kit's hardware-qualified recipes
                             (port/engine/switch2/app/native-worker.cjs,
                             port/civ7-app/thread-code.json) in original code.
                         (3) **Wire behavior** of the :9026 loader
                             (send → half-close → log stream), reimplemented
                             in engine/carrier/civ7js/loader-client.cjs from
                             the kit's save-tools/send_js.py semantics.
                         GPL-2.0 obligations: code and imported data under
                         (2)+(3) must travel with this notice and the kit
                         attribution; do not strip them.
```

Third-party analysis tooling vendored under `tools/` (untouched, their own
licenses, keep their attributions intact): `tools/nstool` (its LICENSE file),
`tools/ghidra-switch-loader` (LICENSE.txt) and the
`ghidra-switch-loader-release` zip artifact. The Ghidra extension itself is
by the adubbz/Ghidra-Switch-Loader project lineage. `firmware/` holds
encrypted, console-derived reference NCAs — see `docs/FIRMWARE.md` for the
handling rules (keys stay outside this repository).

## What this means, plainly

1. **The engine port (`engine/`) derives from no-license research code.**
   ns2jb published no license, so no redistribution right is granted by
   default. What upstream's README does grant, explicitly, is an expectation:
   study it and run it on your own hardware; do not pass it off as your own
   or relicense it. BarbarismJB honors that: the derivation is documented
   here and in `// barbarism:` markers, upstream behavior is preserved
   verbatim wherever it was not adapted, and this repository must not be
   distributed under proprietary terms or with the origin obscured. If
   upstream ever publishes a license, this file and the distribution terms
   must be updated to match it.

2. **The payload side has GPL-3.0 lineage in the blast radius.** CivSwitch
   is MIT, but its README credits the Netflix-N-Hack `inject.js` (GPL-3.0)
   exploit core as the reference for `core.js`'s exploit. BarbarismJB
   payloads execute inside the loader closure that GPL-lineage code
   establishes and call its primitives directly. We do not copy
   Netflix-N-Hack source into this repository, but anyone distributing the
   payloads together with a CivSwitch-derived loader should treat the
   combined work as GPL-3.0-affected and preserve attributions and source
   availability accordingly. Do not strip the CivSwitch / Netflix-N-Hack
   credits from anything derived from them.

3. **Keep third-party attributions intact.** The ns2jb credits (pepsipu,
   kurumuz, cpypwn, shinyquagsire23), the CivSwitch credits (Netflix-N-Hack,
   ufm42, Element2424), and the vendored tools' license files must travel
   with any copy of the corresponding code. This repository's top-level
   README repeats them for visibility; this file is the authoritative record.

4. **The usb-mtp libptp2 subset is LGPL-2.1-affected.**
   `tools/usb-mtp/mtp_probe_libpt2` statically compiles `ptp.c`, the
   `ptp-pack.c` embedded in `libusb1-glue.c`, and `libusb1-glue.c` VERBATIM
   from **libmtp 1.1.23** (LGPL-2.1-or-later) — the same transaction library
   libmtp itself uses, for byte-identical transport parity against the
   console's capmtp responder. A static subset is a derivative work:
   - Source of record: the libmtp 1.1.23 release tarball
     (libmtp-1.1.23.tar.gz, md5 `9d1ead73e678fa2f51a70a933b0bf017`);
     working copy at build time: `/tmp/libmtp-src/libmtp-1.1.23/src/`
     (local file hashes: ptp.c `2e5212e82868c204361f1cf0c33762e5`,
     ptp.h `5d9f3be07b042d6a6f85be778c19a917`,
     ptp-pack.c `b072e4818dae12de79fbc3ffc59a4113`,
     libusb1-glue.c `6195437485a4819d125a7f19b1bc7c1b`).
   - `tools/usb-mtp/libmtp_shims.c` provides the only four libmtp.c/util.c/
     mtpz.c symbols the subset references; everything else is unmodified.
   - LGPL obligations for anyone distributing the BINARY: accompany it with
     the libmtp 1.1.23 source (or a written offer), keep the LGPL notices
     in the carried files intact, and permit relinking of the subset
     (shipping `libptp2-build/*.o` + build.sh satisfies this for object-
     level relinking). The in-repo copy keeps sources out of the tree only
     because the tarball already lives on the bench; do not distribute the
     binary without them.

5. **Scope of use.** Research on hardware you own. Like upstream ns2jb, this
   project installs nothing, persists nothing, and includes no piracy
   capability; a reboot undoes a run. The firmware dump tooling captures
   code Nintendo owns the copyright to — keep dumps and any keys private,
   offline, and inside `dumps/`/outside-the-repo respectively
   (`docs/FIRMWARE.md` states the key-handling policy).

## First-party components (written for BarbarismJB)

| component | origin |
|---|---|
| `payloads/civshim.js` | original (protocol design + implementation), runs against GPL-lineage primitives; ops 12-15 implement the civswitch-kit raw-svc recipes (GPL-2.0 design lineage, original code) |
| `payloads/dumper.js` | original |
| `engine/carrier/civ7js/` | original; loader wire behavior + kit table mapping derived from the GPL-2.0 civswitch-kit (see the derivation tree above); the imported offset values are kit output |
| `engine/switch2/app/{native-worker,worker}.cjs` `rawsvc` backend | original code implementing the kit's hardware-qualified raw-svcCreateThread worker path |
| `engine/lib/{connection,bridge,offsets}.cjs` | adapted from ns2jb (`lib/` transport replaced; offsets loader new) |
| `engine/shared/{config,errors,log,version}.cjs` | new for this port |
| `engine/shared/frames.cjs` (`buildRop`) | new ropchain backend alongside the verbatim ns2jb `build()` |
| `engine/switch2/*` adaptations | ns2jb files, adapted as marked |
| `run.cjs` | adapted from ns2jb `run.cjs` |
| `tools/{dump_recv,svc_scan,gadget_scan,make_test_nso}.py` | original (stdlib-only) |
| `tests/*` | original |
| `DESIGN.md`, `README.md`, `docs/CIVSWITCH-INTEGRATION.md`, `docs/CIVSWITCH-RUNBOOK.md`, `docs/FIRMWARE.md`, `offsets/*` | original documentation (the integration map + runbook cite the GPL-2.0 civswitch-kit as their source; `offsets/civ7-100.json` carries the kit's values with per-leaf provenance) |

## Historical note

This project was developed under the working name `civ2jb` and released as
**BarbarismJB** (0.1.0, 2026-11-10). Any historical mention of `civ2jb` in
notes refers to this project.
