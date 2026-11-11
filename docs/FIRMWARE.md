# BarbarismJB firmware pipeline — acquisition, decryption truth, decompile tooling

Status: 2026-11-10. Everything below was verified today unless marked otherwise.
Companion files: `firmware/23.0.1/MANIFEST.txt` (acquisition record) and
`firmware/23.0.1/unzip_listing.txt` (archive contents).

---

## 0. THE WARNING — read before touching the console

**Firmware 23.5.0 was released TODAY, 2026-11-10 (UTC), and it patches the fs
`Path::Normalize` bug the entire ns2jb/BarbarismJB chain rests on.**

- SwitchBrew marks 23.5.0 with **"Security flaws fixed: yes"** and records that
  the **FS KIP in package2 was updated** — consistent with the project's ground
  truth (static analysis of the ns2jb chain) that the `IFileSystem::GetEntryType`
  cmd-7 `0x301` path-normalization overflow (stage 1) is closed there.
  The specific bug identity is *our* ground truth from the ns2jb tree
  (`repos/ns2jb`, pepsipu/kurumuz lineage); SwitchBrew does not name it.
  Source: https://switchbrew.org/wiki/23.5.0
- **The console must stay on 23.0.1.** There is no downgrade. One update
  destroys the project's hardware path.
- **Keep 90DNS (or equivalent DNS blocking) active on every network the console
  touches.** Set DNS manually per connection (System Settings → Internet →
  Change Settings → DNS Settings: Manual):
  - Americas: primary `207.246.121.77`, secondary `163.172.141.219`
  - Everywhere else: primary `163.172.141.219`, secondary `207.246.121.77`
  - Set both IPv6 DNS entries to `::` (IPv6 bypasses IPv4 DNS filtering).
  - References: ns2jb README "Strongly recommended: stop the console from
    updating" (same IPs); 90DNS original thread
    https://gbatemp.net/threads/90dns-dns-server-for-blocking-all-nintendo-servers.516234 ;
    per-network guide https://consolemods.org/wiki/Switch:Blocking_OFW_Updates
  - DNS blocking is not a guarantee (cached answers, new networks). Verify
    before every session; treat any unknown network as hostile.
- Timeline: 23.0.1 shipped 2026-10-01 → 40 days of safe window → 23.5.0 on
  2026-11-10. First *fix* is in 23.5.0; there was no 23.1/23.2/23.3/23.4 in
  between that touched this bug (23.0.1 is the last exploitable version).

---

## 1. Firmware 23.0.1 — facts

| Fact | Value | Source |
|---|---|---|
| Release date | 2026-10-01 UTC (report timestamp `2026-10-01_01-02-36`; evening 2026-09-30 in the Americas) | NinUpdates https://yls8.mtheall.com/ninupdates/reports.php?date=2026-10-01_01-02-36&sys=hac , SwitchBrew https://switchbrew.org/wiki/23.0.1 |
| Official changelog (all regions) | "Fixed an issue from system version 23.0.0 where software occasionally took a long time to start, pause, or close." | NinUpdates / SwitchBrew |
| System titles updated | sysmodule `sdb` + SystemVersion RomFs `/file` | SwitchBrew 23.0.1 |
| Successor | 23.5.0, 2026-11-10, "Security flaws fixed: yes", FS KIP updated in package2, eShop-gifting feature prep | SwitchBrew https://switchbrew.org/wiki/23.5.0 |
| Versioning note | Switch 1 and Switch 2 share system-version numbering since 20.0.0. Same number ≠ same binaries: each line ships its own NCA set. | project ground truth / THZoria packaging |

Why 23.0.1 and not 23.0.0: the ns2jb exploit chain was validated end-to-end on
23.0.1 + SmileBASIC 4.4.9 (upstream hardware test). Offsets, heap geometry, and
fsp-srv command numbers in `repos/ns2jb` are pinned to this version.

---

## 2. Acquisition paths, ranked

### Path 1 (best; the ONLY complete-for-research Switch 2 source): console-side plaintext dump

Run **after the chain works** (needs stage ≥1 fs compromise / FullPermission):

```
# ns2jb (SmileBASIC host):
node dump-firmware.cjs            # or: node run.cjs --dump-firmware --rpc
# BarbarismJB, once M4 passes:
node run.cjs --dump-firmware
```

- Asks the console's **NCM** for installed system-program IDs, then reads each
  title's `main` (NSO) and `main.npdm` through **CodeFS** — content the console
  has *already decrypted for itself*. No keys needed, no keys ever leave the
  console.
- Output: `dumps/firmware-dump.json` (inventory + per-file SHA-256 + titles
  whose CodeFS was unavailable) plus the binaries. Needs 512 MiB free host-side.
  Re-running clears `dumps/` — move anything you want to keep.
- This yields **Switch 2 system-module NSOs + NPDMs in plaintext** — the only
  such source that exists today. Everything below is a complement, not a
  substitute.

### Path 2 (reference archive; DONE — on disk, verified): THZoria/NX_Firmware

The THZoria/NX_Firmware project repackages the official CDN content with an
automated pipeline. Its 23.0.1 release is the **Switch-1-line packaging** of
23.0.1: **encrypted NCAs**, FAT+exFAT SystemVersion variants.

Downloaded and verified 2026-11-10 (see `firmware/23.0.1/MANIFEST.txt`):

| Item | Value |
|---|---|
| URL | https://github.com/THZoria/NX_Firmware/releases/download/23.0.1/Firmware.23.0.1.zip |
| Release page | https://github.com/THZoria/NX_Firmware/releases/tag/23.0.1 (published 2026-10-01T01:54:25Z) |
| Size | 340,422,248 bytes |
| SHA-256 | `5337647d78584d046b6c8f46792a07c3701d7ee68473620d5008f18fc7604781` — matches GitHub's API asset digest **and** the checksum in the release body text |
| Contents | 238 files, 340,385,792 bytes uncompressed: `*.nca` (encrypted content) + `*.cnmt.nca` (content meta). SystemVersion NCAs: FAT `00e57b67b4dbd750a2df0574cddc123d.nca`, exFAT `16510dde912c6c6894d573f17006f113.nca` |
| Local | `firmware/23.0.1/Firmware.23.0.1.zip` (NOT extracted — extract only when a step needs it, inside that dir) |

Re-download procedure if ever needed (resume-capable):

```sh
cd BarbarismJB/firmware/23.0.1
curl -L -C - --fail --retry 3 -o Firmware.23.0.1.zip \
  "https://github.com/THZoria/NX_Firmware/releases/download/23.0.1/Firmware.23.0.1.zip"
shasum -a 256 Firmware.23.0.1.zip   # must be 5337647d78584d046b6c8f46792a07c3701d7ee68473620d5008f18fc7604781
```

Use: cross-version **structural diffing of shared sysmodules** (fs, ro, ldr, pm,
ncm, sm exist in both console lines) — sizes, section layouts, cnmt version
bumps, and — only with keys, §3 — decompiled comparisons. Also the SystemUpdate
packaging ground truth for M6.

### Path 3 (CDN direct): documented, pointless for our Switch 2 needs

SwitchBrew-documented endpoints (https://switchbrew.org/wiki/Network):

- `sun.hac.%.d4c.nintendo.net` — system-update check, returns latest system
  title listing (JSON). Requires the console's TLS client certificate
  (community tooling like ReSwitched/HacVersionListBot authenticates this way).
- `aqua.hac.%.d4c.nintendo.net` — required-minimum-system-version metadata.
- `atumn.hac.%.d4c.nintendo.net` — CDN serving system-title content (the NCAs
  themselves; `atum.hac` is the eShop-content sibling).

Why it doesn't help for Switch 2:
1. The update-check endpoints are gated by per-console client certificates —
   you need a console to ask in the first place (and the console we care about
   must never ask: §0).
2. `atumn` hands you the same **encrypted NCAs** as the THZoria zip already on
   disk — and for Switch 2 there are **no public keys to decrypt them** (§3).
   You'd be re-downloading, less conveniently and with worse provenance, an
   artifact we already have checksummed.

---

## 3. Decryption truth

**There are no public Switch 2 keys of any kind.** Verified state, 2026-11-10:

- No public `prod.keys` for the Switch 2 line, and no key dumper (a dumper
  needs an exploit first — the boot ROM / TSEC path that worked for Switch 1
  does not exist for Switch 2).
- **hac2l** (hactool's successor, Atmosphere-NX org): repo alive but **dormant
  since 2024-10-31** (last commit "hac2l: implement (almost all of) -t keygen").
  No Switch 2 crypto. https://github.com/Atmosphere-NX/hac2l
- **LibHac / hactoolnet** (Thealexbarney/LibHac): **repository returns 404**
  (deleted or taken private). https://github.com/Thealexbarney/LibHac
- **nsz** (nicoboss/nsz): actively maintained (last push 2026-10-25), but no
  Switch 2 crypto — it cannot derive keys that do not publicly exist.
  https://github.com/nicoboss/nsz
- **nstool** (jakcron/nstool, cloned to `tools/nstool`): same — Switch 1 crypto
  only.

Corollary: the Switch-2-line NCAs (had we a Switch 2 packaging of them) would be
**cryptographically inert forever** until keys leak. The Switch-1-line NCAs in
our reference zip are a different story:

### Switch-1-line NCAs CAN be decrypted — with YOUR OWN Switch 1 prod.keys

If the user supplies a `prod.keys` dumped from their own Switch 1 (never
download keys; the firmware archive must stay key-free), the reference zip's
NCAs decrypt fine — every tool above does Switch 1 crypto. Exact commands
(when keys arrive; nstool is source-only today, build first per §4.3):

```sh
cd BarbarismJB/firmware/23.0.1
unzip Firmware.23.0.1.zip -d extracted      # ~325 MB; keep inside this dir

# nstool: inspect one NCA (auto-loads $HOME/.switch/prod.keys, or -k path)
nstool -k /path/to/prod.keys extracted/00e57b67b4dbd750a2df0574cddc123d.nca
# list the ExeFS (system-program main/control) inside a program NCA:
nstool --showlayout -v -k prod.keys extracted/<some-program>.nca
# extract an NCA's partitions (ExeFS/RomFS) to ./out:
nstool -k prod.keys --exefsdir out --romfsdir out extracted/<nca>
# NSO from a decrypted ExeFS goes straight into Ghidra (§4.1) or rizin (§4.4)

# nsz (pipx/brew install nsz) — decrypt an NCA in place to *.nca plaintext:
nsz --keys /path/to/prod.keys -D extracted/<nca>      # -D = decrypt NCA→NCA
```

Keys handling rules (project policy): keys live **outside** `BarbarismJB/`, are
never committed, never copied into `firmware/` or `tools/`, and never travel
over the console network. We only ever accept them interactively from the user.

---

## 4. Decompile pipeline (all installed and verified today)

### 4.1 Ghidra 12.1.4 + SwitchLoader — primary, verified working

- **Ghidra 12.1.4** (build 2026-09-21) — already present as a Homebrew
  **formula** (there is no `ghidra` cask; `brew info --cask ghidra` fails,
  `brew info ghidra` is the formula). Path: `/opt/homebrew/opt/ghidra/`
  (headless: `/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless`).
  An upgrade to 12.2 is available but not taken (don't churn a working tool).
- **Java**: system java is Temurin **26.0.2.1** and brew's ghidra pulls
  `openjdk@25`; Ghidra 12.x runs fine on these — **empirically verified**.
  The "Ghidra 11.x needs JDK 21" rule does not apply to 12.x. (If someone ever
  downgrades to Ghidra 11.x, `brew install --cask temurin@21` and point
  `JAVA_HOME` at it; the SwitchLoader README also tells *builders* to use
  JDK 21, but its CI builds 1.6.1 against 12.1.2 with newer JDKs.)
- **adubbz ghidra-switch-loader 1.6.1** — prebuilt release zip downloaded to
  `tools/ghidra-switch-loader-release/SwitchLoader-1.6.1-0f38957-Ghidra_12.1.2.zip`
  (9,125,182 bytes, sha256
  `c37b8e8360a5071b47f7a56e2bf467b00e4a6eef884cc3dede17b5ad65298f96`);
  source cloned to `tools/ghidra-switch-loader` (HEAD 9a141a7, 2026-11-02).
  - Installed to the **macOS** user extension dir
    `~/Library/ghidra/ghidra_12.1.4_PUBLIC/Extensions/SwitchLoader/`.
    (Note: on macOS Ghidra ignores `~/.ghidra/`; that cost us one debugging
    round — settings live under `~/Library/ghidra/`.)
  - Built against Ghidra 12.1.2; **verified working under 12.1.4**: a
    hand-crafted minimal NSO0 imported headless with
    "Using Loader: Nintendo Switch Binary" /
    "Using Language/Compiler: AARCH64:LE:64:v8A:default" and saved cleanly.
    Test-crafting script kept at `tools/make_test_nso.py`.
  - Loader formats: NSO0, NRO0, KIP1, MOD0-kernel (0xD5034FDF), SX-KIP1 —
    plus **ZBIC** (Nintendo's zstd NSO variant introduced fw 22.0.0+,
    relevant for modern system modules) unwrapped transparently. It reads a
    MOD0-offset pointer at text+4 (real system NSOs have it; synthetic test
    files must set it to 0 or the loader throws).
  - Bundled script `EnableSwitchIpcJsonExport.java` + IPC analyzer: labels
    `sm:`-registered service names and IPC command numbers using its bundled
    ipc_services.json database — useful for fsp-srv work.
  - **Build from source** (only if a future Ghidra upgrade breaks the prebuilt;
    not built today):
    ```sh
    cd tools/ghidra-switch-loader
    export GHIDRA_INSTALL_DIR=/opt/homebrew/opt/ghidra/libexec
    ./gradlew            # output zip in ./dist — install via the steps above
    ```

**Import a dumped system module (the money command):**

```sh
/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless \
  <project_dir> fw2301 -import dumps/<module>/main.nso \
  -processor AARCH64:LE:64:v8A      # SwitchLoader auto-selected on NSO0 magic
```

Or GUI: `ghidraRun` from `/opt/homebrew/opt/ghidra/bin/`; the SwitchLoader
appears as "Nintendo Switch Binary". NSOs load at image base 0x7100000000;
the IPC analyzer runs with default auto-analysis.

### 4.2 Recommended module analysis order for BarbarismJB

| Order | Module | Why it's in the chain |
|---|---|---|
| 1 | **fs** (fsp-srv service surface) | Stage 1 target: `IFileSystem::GetEntryType` (cmd 7) `0x301` path-normalization overflow; confirm the command table (7/200/202/1002/1009/1200/510/…) on 23.0.1, the BufferedStorage CacheEntry layout, the domain-clone path (stage 1.5), and *what 23.5.0 changed* (diff vs the reference archive's S1 fs once keys exist; and vs S2 dump when M6 lands) |
| 2 | **ro** | Stage 2 beneficiary: our NSO launches under `ro`'s NPDM (program `0x0400000000000037` per ns2jb); `ro:1`/`ro:dmnt` become the process-memory server. Verify ExeFS-object/domain-table assumptions |
| 3 | **ldr** | Stage 2 mechanics: the loader's ExeFS object that gets domain-swapped to the donor FS; its session/table lifecycle |
| 4 | **pm** | Stage 2 launch path: PM IPC for launching under the swapped program/NPDM |
| 5 | **ncm** | `dump-firmware` depends on NCM's installed-content inventory + CodeFS access; also M6 packaging truth |
| 6 | **sm** | Stage 0.5+: every `sm:` service-open the engine performs; verify service names the host must open on 23.0.1 |

All of these land in the Ghidra project from the **console dump** (Path 1,
plaintext, Switch 2). The reference-archive versions (S1, encrypted) are for
cross-version/cross-line diffing only.

### 4.3 nstool (source only, documented)

Cloned with submodules to `tools/nstool` (HEAD cfb826c, 2024-10-14; deps:
libfmt v10.1.1, liblz4 v1.9.4, libmbedtls 2.16.12, libpietendo v0.8.0,
libtoolchain v0.8.0). Build (not executed today):

```sh
cd tools/nstool
make deps && make          # macOS/Linux per BUILDING.md; C++11 toolchain
# binary: ./nstool  — usage per §3 (keys via -k or $HOME/.switch/prod.keys)
```

(There is no cmake; the project moved to plain make. BUILDING.md is the
authority.) There is no prebuilt release zip on its GitHub releases.

### 4.4 rizin — quick-disasm fallback (installed)

`/opt/homebrew/bin/rizin` 0.9.1. For quick symbol/gadget questions without a
Ghidra project:

```sh
rizin -q -c 'aaa; afl' dumps/<module>/main.nso        # list functions
rizin -q -c 'aaa; pdf @ sym.xxx' dumps/<module>/main.nso
rizin -q -c '/c ret' dumps/<module>/main.nso          # gadget search
rz-asm -a arm -b 64 'svc #0x21'                       # encode/verify svc ids
```

rizin 0.9.1 has native NSO support (verified: it recognizes and parses NSO0
headers directly). If a dumped NSO trips its decompressor, fall back to the
Ghidra-loaded image or feed rizin the M0 zero-copy dumps, which are raw memory
images anyway.

---

## 5. Emulation verdict: no usable emulation for this project

- **Eden-NX2**, the first public Switch 2 emulator, released **2026-10-29**
  (Windows; fork of the Eden Switch emulator). It is **HLE, games-only**:
  it boots commercial titles (Mario Kart World, Donkey Kong Bananza) by
  reimplementing OS APIs, with rough performance. Sources:
  https://gbatemp.net/threads/eden-nx2-emulator.686041 ,
  https://www.tweaktown.com/news/114420/first-nintendo-switch-2-emulator-for-pc-is-out-and-it-already-boots-mario-kart-world/index.html
- **There is no LLE** (low-level emulation) of the Switch 2 anywhere: nothing
  boots actual 23.0.1 system modules, package2, or the sysmodule IPC fabric.
  An HLE emulator cannot host our chain: the exploit *is* IPC-against-fs
  sysmodule behavior.
- Therefore: **all dynamic analysis stays on-console**, via the held RPC
  (`ns2jb` stage 3; BarbarismJB M1+ `civshim` on :39381). Static analysis is
  offline (Ghidra on dumps). The emulator is irrelevant to the chain and
  should not be cited as a test path.

---

## 6. What exists on disk right now (inventory)

```
BarbarismJB/firmware/23.0.1/
  Firmware.23.0.1.zip        340,422,248 B  sha256 5337...4781 (verified)
  MANIFEST.txt               acquisition record (URLs, sizes, hashes)
  unzip_listing.txt          unzip -l of the archive (238 files)
  curl_download.log          transfer log
BarbarismJB/tools/
  ghidra-switch-loader/      source clone (9a141a7, 2026-11-02)
  ghidra-switch-loader-release/
    SwitchLoader-1.6.1-0f38957-Ghidra_12.1.2.zip   prebuilt ext (sha256 c37b...8f96)
  nstool/                    source + 5 submodules (cfb826c, 2024-10-14)
  make_test_nso.py           minimal-NSO0 generator used to verify the loader
~/Library/ghidra/ghidra_12.1.4_PUBLIC/Extensions/SwitchLoader/   (installed)
/opt/homebrew/opt/ghidra/   Ghidra 12.1.4 (brew formula)
/opt/homebrew/bin/rizin     rizin 0.9.1
```

All downloaded artifacts are untrusted data: they stay inside `firmware/` and
`tools/`, are never executed, and no keys or key-derived material are stored
anywhere in the project.

## Sources

- THZoria/NX_Firmware 23.0.1 release + API:
  https://github.com/THZoria/NX_Firmware/releases/tag/23.0.1
- NinUpdates report: https://yls8.mtheall.com/ninupdates/reports.php?date=2026-10-01_01-02-36&sys=hac
- SwitchBrew 23.0.1: https://switchbrew.org/wiki/23.0.1 — 23.5.0: https://switchbrew.org/wiki/23.5.0 —
  Network/CDN: https://switchbrew.org/wiki/Network
- hac2l: https://github.com/Atmosphere-NX/hac2l (dormant since 2024-10-31)
- LibHac: https://github.com/Thealexbarney/LibHac (404)
- nsz: https://github.com/nicoboss/nsz — nstool: https://github.com/jakcron/nstool
- ghidra-switch-loader: https://github.com/adubbz/ghidra-switch-loader
  (release: tag `1.6.1-0f38957-Ghidra_12.1.2`)
- Eden-NX2 coverage: GBAtemp/TweakTown links in §5
- 90DNS: GBAtemp thread + consolemods wiki in §0
- Project ground truth: `BarbarismJB/DESIGN.md` (§0 warning), `repos/ns2jb/`
  (README firmware/90DNS/dump-firmware sections, docs/)

## 23.0.1 → 23.5.0 archive diff (2026-11-11) — what the patch touched

Both zips are encrypted (no keys — cnmt headers encrypted too), but a
NCA-id/size diff plus correlation against our decrypted CodeFS dump gives:

- 238 files each; **171 NCAs carried byte-identical** → only ~34 titles
  updated; 33 content NCAs + 34 cnmts rebuilt (~130MB of 340MB).
- Size-correlation verdicts (dumped content vs NCA size, best-match):
  - **BrowserCoreDll (0x85d, 26.3MB): CARRIED identical** (26.8MB NCA, 1.02x
    match) — the WebKit ENGINE WAS NOT UPDATED in 23.5.0. The bench's
    engine research (CSSFontFace UAF, full-chain pages) carries over.
  - **SystemWeb (0x1042) + LibAppletWeb (0x1043): REBUILT** (two 7.1MB NCAs,
    both distinctive matches) — the web applet layer changed. Delta unknown
    (encrypted); could be applet-gate hardening or benign. This is the risk
    item for the update path.
  - **nim / nifm / account: REBUILT** — update/online machinery touched
    (consistent with the fs patch + supernag work landing).
  - **ssl: carried** (2.1MB candidates both identical) — NSS untouched.
  - The 42.1MB rebuilt NCA: out-of-family for BrowserCoreDll (1.6x); most
    plausibly the package2 carrier (kernel + built-ins incl. the PATCHED fs).
- Verdict: engine intact, applet layer + update stack touched. The
  update-to-23.5.0 fork: engine exploit surface survives; applet-launch
  behavior is the unknown; the fs chain definitively dies (confirmed by the
  rebuilt package2-size NCA + scene reports).
