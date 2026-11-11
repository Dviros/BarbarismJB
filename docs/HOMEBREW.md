# Homebrew on the Civ 7 host — survey, verdicts, and the Barbarism app loader (M7)

Research date: 2026-11-10. Repos studied read-only (shallow clones, nothing
executed) in `../repos/` relative to this project root:

| Repo | Commit/tag studied |
|---|---|
| `HBLauncher` (ravensclawx) | `main` @ `18b4748` + tag `v0.2.0` (adds the FTP service) |
| `ftpd-sb` (ravensclawx) | `main` @ `0eef12d` |
| `IZ2S-Platform` (byizmysh) | `main` @ `331c9c1` (v0.22.0) |
| `ns2jb` (pepsipu/kurumuz, pre-existing clone) | — ground truth for the `ro` payload commands |

**Headline answers**

1. **HBLauncher — needs a port, and the port is small.** Its native images are
   host-agnostic freestanding AArch64; everything host-specific lives in the
   PC-side Node host and a table of SDK offsets. It maps code with the same
   `ro`-payload process-memory server BarbarismJB already runs
   (`0x524f0012`-family), just via newer bulk commands (`0x524f001a/b/c`)
   added in the `ns2jb-kurumuz` fork.
2. **ftpd-sb — not applicable as a package, highly reusable as a design.**
   It is not standalone software: it is a *GPU-app front end* (SPIR-V shaders
   only, no native code) for an FTP engine that lives in the HBLauncher PC
   host and drives SmileBASIC's sockets/files over the held RPC. The engine
   (`sdk/host/ftp-native.cjs` + `ftp-server.cjs` at HBLauncher v0.2.0) is
   exactly the job list our M7 first app should generalize.
3. **IZ2S-Platform — works as-is on Civ 7 today, for what it does**, and it
   is the strongest external evidence for this project's feasibility: a
   shipping platform (v0.22.0, Linux) that already attaches to the Civ 7
   (Switch-1 cart 1.0.0) process, creates a vi layer + Vulkan swapchain from
   inside the game process, reads controllers/touch, and runs "GPU shader
   app" modules — all host-driven over the CivSwitch :9026 JS loader. What it
   does *not* do on Civ 7 is run native code (`filesystem:false` in its own
   report), because the ns2jb fs-exploit chain has not been ported to the
   Civ 7 client. That port is precisely BarbarismJB M3/M4; the Barbarism app
   loader (M7) is what IZ2S cannot offer Civ 7 users today.

---

## 1. Per-project verdicts

### 1.1 HBLauncher — verdict: **needs port** (host retarget + payload bulk-map command; launcher/app images reusable as-is)

What it is: a native AArch64 homebrew launcher and app SDK that runs inside
the **SmileBASIC** application process, driven frame-by-frame from a PC host
over the ns2jb held RPC (`README.md:5-8`, `docs/ARCHITECTURE.md:22-27`).
Requires an external `ns2jb-kurumuz` checkout and a verified **4/4** session
before mapping any code (`README.md:69-78`, `host/lib/session.cjs:66-71`).

**How native code gets mapped** (the part we care about):

- The host holds a **KProcess handle** to the app process, constant
  `HANDLE = 0xffff8001` (`host/lib/target.cjs:20`), and opens two channels:
  the app-bridge RPC (`shared/rpc.cjs` from the ns2jb run dir:
  `call-address`, `verify-function`, `read/write/query`) and the fs-endpoint
  process client (`switch2/tools/fs-memory.cjs` + `switch2/process/client.cjs`)
  which fronts the `ro` payload's `ro:dmnt` process-memory server
  (`host/lib/target.cjs:41-57`; ns2jb `engine/switch2/process/client.cjs:42-49`
  looks up `ro:dmnt` through the borrowed fs `sm:` client, `:52-57` exports a
  copy of the fs self-handle).
- Source blocks come from the **app process's own SDK allocator**, called
  through the bridge: `SDK_ALLOCATE = 5732112`, `SDK_FREE = 5616480`
  (SmileBASIC nnSdk module offsets; `host/lib/target.cjs:26-29, 68-81`).
- Code mapping uses the **bulk range commands** of the newer payload:
  `0x524f001a` (map N pages **RX** from one Normal RW block),
  `0x524f001b` (RW), `0x524f001c` (unmap range), plus single-page
  `0x524f0013` and patch `0x524f0014` (`host/lib/target.cjs:21-25`).
  `mapImage` validates the destination VA is free via `query`, then maps in
  ≤16384-page chunks (`host/lib/target.cjs:124-143`). The launcher links at
  `0x08000000` RX / `0x0A000000` RW, apps at `0x09000000`/`0x0B000000`
  (`launcher/link.ld`; `host/lib/runtime.cjs:28-29, 190-258`).
- Cache publish: since 2026-10-28 the range command's permission change alone
  publishes new instructions (a 47 KB launcher map dropped ~94 s → ~0.25 s;
  per-64-byte-line `0x524f0014` publishing is now opt-in via `HBL_PUBLISH=1`)
  — `host/lib/target.cjs:148-154`. Unmap quirks (bulk unmap rejects exactly
  page-rounded sources with 0xD401 → allocate one slack page; per-page
  fallback costs ~30 ms/page) are documented at
  `host/lib/target.cjs:192-244` and `host/lib/runtime.cjs:730-731`.
- Our cloned ns2jb payload tops out at `0x524f0016`
  (`engine/switch2/ro/payload/process.c:80-198`): `0x524f0012` maps **one**
  caller-owned RW page into a free destination as code
  (`map_code` + `process_permission(...,5)` with rollback on failure,
  `process.c:178-193`), `0x524f0013` unmaps it (`process.c:194-198`),
  `0x524f0014` patches/publishes 16 bytes with expected+readback
  (`process.c:126-162`, `publish_code` does `dc cvau`/`ic ivau` at
  `process.c:23-31`). BarbarismJB's engine has already demonstrated this
  path in the Civ 7 process.

**What is SmileBASIC-specific** (i.e., what a Civ 7 port must replace):

| Piece | SmileBASIC assumption | Civ 7 replacement (already exists?) |
|---|---|---|
| App bridge | ns2jb `shared/rpc.cjs` (`call-address` into SB interpreter thread) | civshim :39381 ops CALL/READ/WRITE/QUERY/ALLOC/FREE (M1, `payloads/civshim.js`) |
| Allocator | nnSdk `allocate` @ +5732112, `operator delete` @ +5616480 (`target.cjs:26-29`) | civshim op 6/7 (game `calloc`/`free`) — same role |
| SDK symbol table | audited `sdk/sdk-symbols.json` (hid/vi/os/audio offsets: `runtime.cjs:311-312, 355-394, 71`), imports resolved as `sdk+offset` (`runtime.cjs:843-869`) | M0 dump of Civ 7 `sdk` module produces the equivalent table; better: IZ2S-style live SysV-hash resolution by symbol name (§1.3) so offsets never go stale |
| Input | `nn::hid` pad fns at fixed offsets, verified against archived bytes (`runtime.cjs:303-351`); touch via import slot (`runtime.cjs:396-420`) | same `nn::hid` exports exist in Civ 7's nnSdk — resolve by name |
| Display | vi layer via SDK calls (`OpenDefaultDisplay`, `Layer::Layer`, `LayerCreationSettings(1920,1080)`, `Layer::Open`, `GetNativeWindow` — `host/lib/vi-layer.cjs:8-33`); Vulkan dispatch from SmileBASIC's "compatibility module" export table (`host/lib/dispatch.cjs:6-13`, `host/lib/inspect.cjs`) | same `nn::vi` exports + Civ 7's graphics module (see §1.3 — IZ2S proved this on Civ 7) |
| Threading for apps | `nn::os` CreateThreadWithCoreNumber/Start/Wait/Destroy at sdk offsets, app pinned to core 1 "SmileBASIC is on 0" (`runtime.cjs:956-1036`) | civshim op 8 THREAD_CREATE (`pthread_create`+`longjmp` forged jmp_buf) — the M2 machinery; core pinning via affinity API from M0 RE |
| Keep-alive | ns2jb's SmileBASIC activity heartbeat | not needed (Gameface stays foreground) — already dropped in our engine port |

**App package format / SDK needs** (`docs/SDK.md`, `host/lib/packages.cjs:15-17`):
a package is `apps/<id>/manifest.json` (`abi: 3`, `kind: native`, limits
`heap_bytes/stack_bytes/frames`) + built `code.bin` (RX, linked at a fixed
`--code-base`), `data.bin` (RW, zero-filled + copied), `report.json`
(entry/dataBase/bssEnd/hashes). Images are freestanding
(`-ffreestanding -nostdlib -fno-pie -mcmodel=large -mbranch-protection=bti`,
`launcher/build.sh:12-16`); crt0 lands with `bti jc`, switches to the
host-provided stack, and offers `_spawn` for threaded launch
(`sdk/src/crt0.S:13-56`). The only host/image interface is
`struct hbx_ctx` (592 B, ABI 3) with heap/stack/control/log/catalog and
`gpu`/`input` blocks that may be zero (headless profile uses
`FLAG_NO_AV`, `runtime.cjs:31, 763`).

**Port cost estimate**: `host/lib/target.cjs` retarget (bridge + allocator +
process client — our engine already has all three), a Civ 7
`sdk-symbols.json` from the M0 dump, and either (a) looping `0x524f0012`
per page (fine for ≤100 KB images: one IPC per page) or (b) porting the
kurumuz bulk `0x524f001a/b/c` commands into our Zig `ro` payload (a loop
around `map_code`+`process_permission`, plus the permission-change-publishes
behavior). The launcher image itself and ABI-3 apps (hello-cpu, gpu-triangle,
Animal Crossing / Twilight Princess ports) then run unmodified, headless
first, GPU later.

### 1.2 ftpd-sb — verdict: **not applicable as-is** (it is an HBLauncher GPU-app skin); **port the engine, not the app**

- It is an HBLauncher **GPU app**: `app.json` declares
  `"format": "hblauncher.gpu-app"`, shaders (vert/frag/compute SPIR-V) and
  `"sdk": {"services": ["ftp"], "ftpPort": 5000}` — there is no native code
  in the package (`ftpd-sb/app.json`). The README is explicit: *"This is an
  HBLauncher GPU app, not an NRO for a conventional custom-firmware
  launcher. The PC host must remain running throughout the session."*
  (`README.md:44-47`) and it requires HBLauncher **v0.2.0+** because the
  FTP engine ships in the host (`README.md:22-24, 110-111`).
- The engine (HBLauncher v0.2.0 `sdk/host/ftp-native.cjs`,
  `ftp-server.cjs`, `ftp-service.cjs`, `sdk/docs/ftp.md`) drives **all**
  sockets and files through the SmileBASIC held RPC using an audited
  function table (`sdk/native/ftp-functions.json`: `nn::socket`
  Socket/Bind/Listen/Accept/Poll/Send/Recv + `nn::fs`
  OpenDirectory/ReadDirectory/OpenFile/ReadFile/WriteFile(via the
  six-register worker)/Flush/Commit/CreateFile/Delete/Rename). The GPU app
  only presses start/stop through a shared control block.
- **Storage exposed** (`README.md:78-86`, `sdk/docs/ftp.md`): `/save`
  (SB `save:/`, RW), `/tmp` (RW), `/rom` (SB romfs, RO). *"This does not
  expose the SD card, other games' saves, or the host PC filesystem. The
  title's SD filesystem request is denied on the tested environment."*
  One client, passive mode, anonymous, 32 KiB chunks, commits after writes.
- **A Civ 7 version would expose**: `save:/` (Civ 7 savedata — RW, with the
  XSTRIG trigger protected), `rom:/` (Civ 7 RomFS — RO), and — this is the
  BarbarismJB-only part, post-PID→1 — **BIS** (system/user partitions) and
  **any-title CodeFS/RomFS** via the fs endpoint (OunceCake-style game
  mounting; IZ2S embeds exactly this as `core/filesystem/ouncecake`).
- **Standalone or HBLauncher app?** Neither, for us: the sensible BarbarismJB
  shape is a *native headless service inside the Civ 7 process* (M7 first
  app, §2.5) using civshim's already-ROP'd `nn::socket`/`nn::fs`, with the
  host FS endpoint only for the BIS/CodeFS mounts native code can't reach
  pre-PID→1. ftpd-sb's protocol state machine (`ftp-server.cjs`: USER/PASS,
  PASV/EPSV, LIST/MLSD/NLST, RETR/STOR/APPE, REST, SIZE, DELE/RMD/MKD/RNFR/RNTO,
  30 s data / 120 s control idle timeouts) is a ready-made spec to port.

### 1.3 IZ2S-Platform — verdict: **works as-is on Civ 7 (host-driven)**; not something we port — the reference implementation and the benchmark

What it is (v0.22.0, Linux x64/ARM64 only): a PC "control panel" + console
launcher platform supporting **two hosts — SmileBASIC 4 *and* Civilization
VII** (`README.md:3-7`), with bundled apps (File Exchange FTP, Book Reader,
Super File Bros. file manager, IZPSX PlayStation emulator on PCSX-ReARMed)
and an app/module store format (`.izm`, `izlauncher.module` +
`hblauncher.gpu-app` payloads). Civ 7 delivery: LDN Wi-Fi from a Linux PC
(needs user `prod.keys`) or USB input devices (Cardputer ADV / ARM boards)
typing the 87-line lobby-chat payload; persistence via an `IZ2S.Civ7Save`
loader save and **Load Game → "Awaiting payload"** (`README.md:89-95`,
`COMPATIBILITY.md:12-18`, `engines/CivSwitch/INTEGRATION.txt`).

It **embeds upstream CivSwitch (Gezine, MIT)** as its Civ 7 engine
(`engines/CivSwitch/engine.json`: `consolePort: 9026`,
`upstream: github.com/Gezine/CivSwitch`) — the same :9026 one-script-per-
connection JS loader BarbarismJB builds on. On top it layers:

- **JS-side RPC**: scripts evaluated over :9026 install a
  `window.__iz2sCivRuntime` dispatch; requests are framed with bounded ASCII
  markers, never replayed after a timeout (`engines/CivSwitch/runtime/client.cjs:1-30`).
  This is the same design as our civshim (which additionally frees the JS
  thread by serving from a native socket loop).
- **Live symbol resolution**: named exports are resolved at runtime in the
  *live Civ 7 module's* ELF SysV hash table (MOD0 → DT_HASH walk);
  *"SB4 SDK offsets and instruction gadgets are never treated as Civ7
  addresses"* (`runtime/native.js:1-30`). Strongly recommended pattern for
  our `sdk-symbols` equivalent — pin the module by hash, resolve by name.
- **Display from inside the game process — proven**: the Civ 7 graphics
  driver module is located via the game's `nvnBootstrapLoader` import and
  verified to export `vk*` symbols (`runtime/driver.cjs:4-27`); the display
  flow creates an independent vi layer (`nn::vi OpenDefaultDisplay`,
  `Layer::Layer`, `LayerCreationSettings(1920,1080)`, `Layer::Open`) and a
  Vulkan 1.4 instance/device/swapchain, with presentation explicitly gated
  (`display.verified && display.presentationAccepted` required before the
  menu starts; `runtime/display.cjs`, `runtime/run.cjs:16-21`). The frame
  loop then drives `vkAcquireNextImage2KHR`/`vkQueueSubmit`/`vkQueuePresentKHR`
  and reads `nn::hid GetNpadState`/`GetTouchScreenState` resolved by name
  (`runtime/frame-loop.cjs:3-8, 20-34`).
- **Apps = "GPU shader apps"**: the same `hblauncher.gpu-app` format as
  ftpd-sb; pipelines are created host-side over RPC on the retained launcher
  surface (`runtime/gpu-app.cjs:1-20`). IZPSX adds a native engine image
  (`"native": {"format": "iz2s.native-app", "abi": 5, "code":
  "native/shim.bin"}`, `modules/izpsx/switch/app.json`) executed by the
  **native SD supervisor** — but that supervisor requires the ns2jb fs
  chain: *"A single application-owned pthread executes the SD supervisor.
  The retained FS endpoint is used only to borrow capabilities and map the
  initial helper"* (`core/console/sd-launcher/bootstrap.cjs:1-2`), mapping an
  `IZNATRL1` relocatable image (fixup table constrained by ADRP/PREL32 reach,
  `core/console/sd-launcher/relocatable/README.md`) through the same
  `ro`-payload process commands. **On Civ 7 the loop reports
  `filesystem:false`** (`frame-loop.cjs:34` report literal) — no fs chain, so
  no native execution, no SD apps; Civ 7 sessions run host-driven RAM GPU
  apps only. FS acquisition remains SmileBASIC-only and probabilistic
  (30–40 %/attempt, `FAQ.md:37-41`).
- **OunceCake inside**: `core/filesystem/ouncecake/UPSTREAM.json` vendored
  from `misshexa66/OunceCake` (GPL-2.0, 2026-10-26) — the any-game
  romFS/exeFS FTP mounter over the ns2jb fs endpoint (public port 2121).

**Can it attach to a non-SmileBASIC host?** Yes — that is its headline
feature (Civ 7 today; Balatro announced "within a week" of the dev getting
a cart, `README.md:5`). Its host abstraction is the engine descriptor
(`engines/*/engine.json` + adapter), so new hosts are first-class.
**BarbarismJB's differentiation**: IZ2S's Civ 7 path is tethered shader
composition with no native code, no console-side autonomy, and no BIS/SD;
Barbarism M3–M7 gives Civ 7 the full ns2jb end state (native RX pages in the
game process, fs FullPermission, shell) that IZ2S only has on SmileBASIC.

### 1.4 Ecosystem snapshot (Nov 2026, web)

- **ns2jb** (pepsipu/Sammy Hajhamid, 2026-10-22): first software-only
  Switch 2 jailbreak; integer overflow in the SmileBASIC 4 interpreter →
  userland → fs exploit → native code "with the permissions of ordinary
  system modules"; tethered, fw 23.0.1. Covered by
  [TechPowerUp](https://www.techpowerup.com/354036/nintendo-switch-2-gets-its-first-software-only-jailbreak-with-help-from-openai-codex)
  and [Ars Technica](https://arstechnica.com/gaming/2026/10/switch-2-jailbreak-gives-hackers-new-ways-to-run-homebrew-and-mod-games).
- **WebKit port** of the entry point on 23.0.1 (no game purchase needed):
  [r/switch2hacks thread](https://www.reddit.com/r/switch2hacks/comments/1xeg1mt/).
- **HBLauncher** demonstrated ~24 h after ns2jb:
  [NotebookCheck](https://www.notebookcheck.net/Nintendo-Switch-2-Homebrew-Launcher-reportedly-demonstrated-as-jailbreak-app-disappears-from-eShop-listings.1432482.0.html).
- **mac2jb** ([cpypwn/mac2jb](https://github.com/cpypwn/mac2jb), "etawen
  untether"): all-in-one macOS tool with **both** the ns2jb (SmileBASIC
  4.4.9/demo 4.4.6) and CivSwitch (Civ 7 Switch-1 cart 1.0.0, ~20–25 min USB
  chat delivery) paths. Per its README: on the CivSwitch path *"the CivSwitch
  loader does not expose ns2jb's held rpc session"* and *"MintBrew, SaveKit
  and the other ns2jb homebrew choices do not run through this path in this
  build"* — Civ 7 users get JS payloads, the boot trigger, and save export
  only. **MintBrew** is cpypwn's SmileBASIC-held-RPC **GPU-app launcher**
  (Stremio, DOOM, Froggy Road, OunceCake, ftpd-sb, CHIP-8; explicitly "does
  not run arbitrary CPU application code"); **native ABI-3 HBLauncher
  packages** load only "after a fresh Cellenseres or kurumuz held rpc
  session" (i.e., SmileBASIC). It also installs **Artemis** save-based
  Lua-RPC/FTP launchers into other demo games (Seedsow Lullany, Nora,
  Hamidashi) + Balatro cart.
- **OunceCake** ([release thread](https://www.reddit.com/r/switch2hacks/comments/1xf3lgh/switch_2_game_romfs_and_exefs_dumping_tool)):
  unencrypted romFS/exeFS dumping over FTP (port 2121) from an ns2jb session.
- **CivSwitch** ([Gezine/CivSwitch](https://github.com/Gezine/CivSwitch),
  [GBAtemp](https://gbatemp.net/news/civswitch-offers-a-new-offline-entrypoint-for-switch-2-homebrew.686115),
  [exploit explained](https://www.reddit.com/r/switch2hacks/comments/1xlhsrp/civilization_vii_exploit_explained),
  [walkthrough](https://www.reddit.com/r/switch2hacks/comments/1xll4wf/civswitch_hack_start_to_finish)):
  the Civ 7 multiplayer-chat XSS → :9026 JS loader; offline entry, persistent
  boot trigger.
- **Nobody has demonstrated native (RX-mapped CPU) homebrew from a non-
  SmileBASIC game-process host.** IZ2S is the closest (Civ 7 vi/Vulkan/
  input/shader-apps, host-driven, `filesystem:false`); mac2jb explicitly
  excludes it on Civ 7. Barbarism M3+M7 would be the first.

---

## 2. M7 — the Barbarism app loader

Goal: load and run native homebrew images **inside the Civ 7 process**, from
the host PC, on top of what M1–M5 already provide (civshim bridge, THREAD
machinery, fs endpoint, `ro` payload with the 0x524F00xx process server).
Adopt the HBLauncher ABI-3 package format verbatim (manifest.json + code.bin
+ data.bin + report.json, fixed-base freestanding AArch64 with BTI) so the
existing ABI-3 ecosystem (hello-cpu, gpu-triangle, the Animal Crossing and
Twilight Princess ports) runs with zero source changes, headless profile
first.

### 2.1 Prerequisites (all exist after M4/M5)

- `ro` payload sysmodule with the process-memory server on `ro:dmnt`
  (commands 0x524F0010–0x524F0016; `engine/switch2/ro/payload/process.c`).
- fs endpoint with a transferred **KProcess handle** to the Civ 7 game
  process (ns2jb's `exportHandle(0xffff8001)` pattern,
  `engine/switch2/process/client.cjs:52-57`) and the process client
  (`client.request(id, handle, values)`, `:66-78`).
- civshim :39381 ops: CALL (call_rop, ≤6 args), READ/WRITE (zero-copy at
  address), ALLOC/FREE (game calloc/free), THREAD_CREATE
  (`pthread_create(&t, NULL, longjmp, jb)` with a forged jmp_buf — the M2
  ROP machinery), THREAD_JOIN, SLEEP, UPD_OFFSETS.

### 2.2 Loading an image (host procedure)

1. **Transfer**: read `code.bin`/`data.bin` on the PC, sanity-check
   `report.json` hashes (as `runtime.cjs:198` does), then civshim ALLOC a
   source block in the game heap (`code.length + one slack page`, see the
   0xD401 unmap quirk below) and WRITE the image into it (op 4 recv's
   straight into the block — memory-to-wire in reverse).
2. **Map RX**: pick a free destination VA via QUERY (mirror HBLauncher's
   fixed bases 0x09000000/0x0B000000, verify free, refuse overlap with a
   resident image). Then either:
   - *M7.0*: loop the process client's `map()` (0x524F0012) once per page —
     one fs-endpoint IPC per 4 KB; a 47 KB launcher ≈ 12 calls, fine.
   - *M7.1*: extend the Zig `ro` payload with kurumuz-style bulk commands
     (`0x524F001A/B/C`) — a loop over `map_code` + one
     `process_permission` finalize, matching the observed
     "permission change publishes instructions" behavior
     (`HBLauncher host/lib/target.cjs:148-154`). Keep `0x524F0014` available
     as the explicit `dc cvau`/`ic ivau` publisher for rewritten lines.
   - Data region: map RW (0x524F0012-variant with permission 3, or plain
     ALLOC + WRITE since the loader never needs data at a magic VA — but the
     ABI links .data at a fixed base, so map it).
3. **Verify**: READ back the mapped code and hash it (HBLauncher's
   `verify-function` gate before any `call-address`,
   `target.cjs:87-93`); only then is the entry callable.

### 2.3 Entry bootstrap

- **Threaded (preferred)**: build the app's real thread with civshim
  THREAD_CREATE — the M2 forged-jmp_buf ROP chain sets pc to the image's
  `_start` (an HBLauncher-style crt0 with `bti jc` landing, stack switch to
  an ALLOC'd stack, x0 = ctx block) — the host then **polls** a status word
  in the ctx block with small READs and streams the app's log ring, exactly
  the shape of HBLauncher's `runThreaded` (`runtime.cjs:960-1036`), minus
  its SmileBASIC thread-parking step. Nothing blocks the JS thread for
  longer than one poll; the game keeps rendering; the app runs for minutes,
  not frame budgets.
- **Blocking (fallback, matches HBLauncher's launcher loop)**: one civshim
  CALL into `_start` per bounded entry (HBLauncher uses 720 frames = 12 s,
  `docs/ARCHITECTURE.md:24-27`). CivSwitch's loader already tolerates
  blocking calls (`accept`/`recv` block the JS thread); treat ~15 s as the
  practical ceiling and return control between entries.
- **ctx block**: allocate one page, fill per ABI 3 — magic/abi/size, heap
  (ALLOC), stack base/size, control page, log ring, assets table; zero the
  `gpu`/`input` sections and set the no-AV flag for the headless profile
  (`runtime.cjs:762-800` is the reference fill). `args[8]` carries
  sequence/frame-budget.

### 2.4 Host tooling

`tools/app_loader.cjs` (new): scan `apps/`, validate manifests/hashes
(HBLauncher `packages.cjs` logic is a direct port), map/verify/enter, poll
status, stream logs, handle exit + unmap (bulk first, per-page fallback,
leak-and-report on stuck sources — `target.cjs:192-244` semantics). CLI:
`node run.cjs --app apps/hello-cpu`.

### 2.5 Minimal first app: headless FTP server ("barbarftp")

Generalize ftpd-sb's job list into a native ABI-3 app with `display:
headless`:

- **Protocol**: port `ftp-server.cjs`'s state machine 1:1 to C (commands and
  timeouts listed in §1.2; ~1 day of work, it is a clean async loop).
- **Transport**: `nn::socket` (Socket/Bind/Listen/Accept/Poll/Recv/Send/
  Close) imported via an SDK import table — M0's dump yields Civ 7 nnSdk
  offsets for the same symbols ftpd-sb's `ftp-functions.json` names;
  resolve-and-verify exactly like HBLauncher `resolveImports`
  (`runtime.cjs:843-869`), or better, resolve live by SysV hash (§1.3).
  CivSwitch's core.js has already ROP-proven the socket set on this exact
  game build.
- **Storage tiers**:
  1. `save:/` + `rom:/` in-process via `nn::fs` (title-owned mounts; the
     ftpd-sb feature set, with our XSTRIG/`/main` donor paths protected by
     an explicit deny-list).
  2. Post-PID→1: BIS and any-title CodeFS/RomFS through **host-side fs
     endpoint mounts** (OunceCake pattern), surfaced over FTP by having the
     native app forward those two roots to the host bridge — or simpler for
     M7.0: expose only the in-process mounts natively, and let the M5 shell
     (`ls/cat/put/get` + `mount`) cover BIS/CodeFS. The FTP surface and the
     shell then converge in M7.1.
- Success criterion: FileZilla on the LAN sees `/save` and `/rom` of Civ 7,
  transfers run at LAN speed (no per-CHUNK RPC round-trips — the wireless
  debugging bridge is what caps ftpd-sb at "limited" speed,
  `ftpd-sb/README.md:95-99`; native sockets avoid that entirely).

---

## 3. Display / input reality check

- **The game is foreground and Gameface owns the screen** through Civ 7's
  own presentation. Homebrew must not tear that down; a second presentation
  from the same process is however *publicly proven*: IZ2S creates an
  independent vi layer + Vulkan 1.4 swapchain **inside the Civ 7 process**
  and presents to it every frame (`engines/CivSwitch/runtime/display.cjs`,
  `driver.cjs:4-27`, `frame-loop.cjs`), with `nn::hid` pad/touch state read
  by name (`frame-loop.cjs:3-8`). Their recorded caveats are design
  guidance: retain the display (never destroy the swapchain mid-session —
  they saw a disconnect on `vkDestroySwapchainKHR`), hide/show layers
  carefully (a hide crashed the host game once), and pin the graphics module
  by hash per game version.
- **For M7 the loader stays headless/network-oriented** (FTP, shell, dumps):
  zero display risk, and it is strictly more than mac2jb offers Civ 7 users
  today. A display-capable profile ("M8" candidate) would reuse the IZ2S
  recipe: locate the graphics module via the game's `nvnBootstrapLoader`
  import, build a Vulkan dispatch from its `vk*` exports, `nn::vi`
  OpenDefaultDisplay/Layer(1920×1080)/Open → `VK_NN_vi_surface` swapchain,
  then either (a) HBLauncher's native UI renderer mapped as an ABI-3 image
  with the `gpu` ctx filled, or (b) IZ2S-style host-driven shader apps.
- **Input** is not a blocker either way: `nn::hid` exports resolve by name
  in the live module; the ABI-3 ctx accepts per-source pad entrypoints and
  degrades to zero when unverified (HBLauncher `runtime.cjs:303-351`).

## 4. Open questions

1. **BTI on mapped pages** — HBLauncher compiles images with
   `-mbranch-protection=bti` and lands on `bti jc` (`launcher/build.sh:13`,
   `sdk/src/crt0.S:21`), implying Switch 2 enforces BTI on RX pages created
   via `MapProcessCodeMemory`. Keep the same flags; verify on hardware in M7.
2. **Bulk range commands** — confirm the kurumuz `0x524F001A/B/C` semantics
   (source-block size accounting, the exactly-page-rounded 0xD401 rejection,
   permission-change-publishes) before reimplementing in the Zig payload;
   until then M7.0 per-page mapping is the fallback.
3. **jmp_buf mangling** (M0 unknown, `DESIGN.md` §9.1) gates the threaded
   entry; the blocking entry is the fallback if the guard can't be read.
4. **Watchdog/UI-thread tolerance** for long blocking CALLs (fallback mode)
   — the loader tolerates blocking today, but 12 s entries inside the
   Gameface render loop are untested; the threaded path avoids the question.
5. **Civ 7 nnSdk export surface** — are `nn::fs`/`nn::socket`/`nn::hid`/
   `nn::vi` all exported (statically linked, name-resolvable) in the cart
   1.0.0 build, and do imports need the "defined export" checks of
   `runtime/native.js`? M0 dump answers this; IZ2S's success with hid/vi/
   os strongly suggests yes.
6. **SDK imports table** for apps (`manifest.json "imports"`) — decide
   whether BarbarismJS pins a Civ 7 `sdk-symbols.json` (HBLauncher model)
   or resolves live by SysV hash (IZ2S model). Recommended: live-by-name
   with per-symbol instruction-hash pinning, so game updates only need a
   module re-pin.
7. **IZ2S interop** — their Civ 7 engine and ours both ride the same :9026
   loader; decide whether M7 tolerates a concurrent IZ2S session (probably
   not: one JS runtime, one :39381 listener) and whether we care.
8. **`.izm` / GPU-app support** — out of scope for M7 (no native loader for
   shader-only packages is needed; they are a host-driven display feature),
   revisit with M8 display.
