# CAPSRV2-AUDIT — Send-to-Smartphone / capsrv2 static reverse-engineering (fw 23.0.0 JPN)

Full RE pass over the stated target, 2026-11-12. Artifacts:
`/tmp/bjbresearch/caps2work/` (album.elf, capsrv2.elf, both Ghidra-analyzed
in gproj/, all decompile dumps). All offsets = NSO .text vaddrs (identity:
file offset − 0xE8 in the corrected-ELF wrappers; mkelf scripts in
/tmp/bjbresearch/caps2work/mkelf_album.py, mkelf_capsrv2.py).

## Headline verdict

**THE LANE DOES NOT EXIST IN THIS FIRMWARE.** The S1 "Send to Smartphone"
attack model (console becomes SoftAP at 192.168.0.1, Mac joins and throws
arbitrary HTTP at a system server) is **not present anywhere in fw 23.0.0
JPN**. Exhaustive negative proof, then what capsrv2 actually is, then the
audit of its real (IPC) surface. **The mission's premise — capsrv2.bin
hosting the QR/HTTP smartphone flow — is disproven at the NPDM level before
any disassembly: capsrv2 has zero network services.**

## 1. Architecture map (who is what)

### Title identification (NPDM parse, tools/npdm.py)

| Title | Name | Servers | Clients (net-relevant) |
|---|---|---|---|
| 0400000000000071 | **capsrv2** | caps2:r, caps2:s | auddmg:u, audsmx:u, fatal:u, **gsv:s4**, srepo:u, time:u |
| 0400000000000022 | capsrv | caps:a, caps:c, caps:sc, caps:ss, caps:u | (no bsd/nifm/wlan) |
| 040000000000001b | capmtp | capmtp | caps:a, fatal:u, ns:ro, set:sys, **usb:ds** |
| 040000000000100d | Album (photoViewer) | (none) | **bsd:a**, nifm:s, sfdnsres, **lp2p:m, ldn:m** (monitor-grade), caps:a, caps:ss, chat:alb, ssl |
| 040000000000100e | Setting | (none) | bsd:a, nifm:a, **capmtp** (client), ldn:m |

capsrv2 FAC flags = 0 (NO filesystem access at all), 51 basic syscalls, no
IPC-exotic caps. It is a **compute service** (video encode/mux/thumbnail),
not a network service.

### What capsrv2 actually is

Strings + decompile show the Android-lineage media stack:
`nn.capsrv2.VideoRecording / AudioRecording / RecordingServer / MovieMuxing /
ThumbEncoding / MainThread`, full libjpeg-turbo 1.5.0, MediaMuxer/MPEG4Writer
threads, MediaCodec-style MIME tables (video/av01, audio/opus, csd-hevc...).
It **serves caps2:r/caps2:s to the Album applet** for background video
recording (game clip capture) and consumes **gsv:s4** (GPU video encoder
service, title 0x84) via nvn sync fences. "RecordingServer" (thread named at
capsrv2 0x1d9xx region) = the recording IPC server, NOT a network server.

### The S1 flow for contrast (switchbrew 11.0.0 + not-an-aardvark RE)

S1: photoViewer applet = the host — gained `bsd:s` (server-mode sockets),
`lp2p:sys` (WiFi-Direct AP), RomFs `/http/index.html` web UI; QR1 = WIFI: barcode,
QR2 = `http://192.168.0.1/index.html`; endpoints `/data.json` (ConsoleName,
FileType, FileNames, DownloadMes...) and `/img/<filename>`; **no auth token —
WPA2-PSK join is the only gate**; one DHCP client, one request at a time,
known DHCP-lease retry bug. libcurl absent — hand-rolled HTTP.

## 2. The negative proof (how the lane was killed)

Every step is byte-exact, reproducible from /tmp/bjbresearch:

1. **capsrv2.bin strings**: no http, no 192.168, no smartphone/scanner/QR/
   SSID/token, no data.json. Its only "application/" & "album" strings are
   libjpeg MIME/metadata tables (0x11fe31..0x121a30).
2. **Whole-dump sweep**: `192.168.0.1`, `data.json`, `WIFI:S:` have **ZERO
   occurrences** across all 26 decompressed system modules
   (/tmp/bjbresearch/nso-out/*.bin) AND all 20 applet mains decompressed from
   the dump (System, Album, Setting, Viewer, MiiEdit, Overlay, MyPage,
   SystemWeb, LibAppletWeb, News, Splay, LibAppletOff, Maintenance, ...).
   `switch_` SSID prefix: absent. `htdocs` hits (System c2a1de, Setting
   d933e2..., SystemWeb/LibAppletWeb/LibAppletOff) are **offlineweb3 local
   document paths** ("[Offline] Error: .htdocs/ must be contained in
   documentPath") — the offline-web applet, not a network server.
3. **Album applet deep-dive** (15.6MB decompressed, Ghidra-analyzed):
   - The only `/index.html` (VA 0xc137e0) sits inside **nghttp2's static
     header table** (94-entry table at 0xac2428-0xac2cf8; `/index.html` is
     the RFC-7541 spec example for `:path`). Decoy — not server code.
   - The Content-Length/Content-Type/`Server:` builders (FUN_00191a2c,
     FUN_00194aa0, FUN_0018a0ec) are **libcurl 7.64.1 client internals**
     (NintendoSDK_libcurl-23_2_3; User-Agent/Proxy-Connection handling).
   - No `bind`/`listen`/`accept` server loop exists: the bsd:a client init
     (FUN_001b8160: bsd:s→bsd:a→bsd:u fallback) connects to socket2sf
     IClient; port-80 constants found are curl/DNS/Telemetry client code.
   - NPDM SAC: Album has **bsd:a** (applet sockets — outbound), **lp2p:m**
     and **ldn:m** — both monitor-only interfaces (lp2p:m =
     ISfMonitorService: Initialize/GetGroupInfo/GetLinkLevel only; ldn:m =
     IMonitorService: GetState/GetNetworkInfo/... — per switchbrew LDN
     services). **No lp2p:sys, no bsd:s, no OpenAccessPoint anywhere.**
   - switchbrew 23.0.0 photoViewer entry: only /lyt /message /sound RomFs
     updates — no /http/ RomFs.
4. **RomFs caveat**: the dump carries main+npdm only. The S1 web UI lived in
   RomFs — but the **server code** (bind/accept/URL router) would still have
   to live in main, and it does not exist. Strings would exist. They don't.

**Conclusion: on 23.0.0 JPN, the Send-to-Smartphone HTTP server was removed
or fully reworked out of every process. The Mac-joins-AP attack model has no
target in this firmware.** (What the S2 QR panes — TTS_QRCode_Inside/Outside,
QREncoder-21_2_0 linked into every SDK applet — now encode could not be
determined statically: .data relocation tables aren't in the decompressed
segments. If the feature still exists it's client-side/curl-mediated.)

## 3. caps2:r / caps2:s IPC audit (the surface that IS there)

Server registration in capsrv2 main (FUN_00006530 → FUN_0001cc70):
`caps2:s` registered with 4-session manager (object vtable @0x152048 →
0x14de40), `caps2:r` with 3-session manager (0x152058 → 0x14dec0). Any
system process can connect subject to its own SAC (Album 0x100d and am hold
caps2:r; creport holds caps2:s).

### caps2:s (9 methods, vtable 0x14de40+0x20)

| Slot | Offset | Behavior |
|---|---|---|
| 4 | 0x1f910 | → FUN_0004f6c0 (recording control, 6 scalars) |
| 5 | 0x1f950 | → FUN_000509c0 (buffered variant, u16 sub-params) |
| 6 | 0x1f990 | state-gate thunk (Ghidra undefined; bytes: adrp/ldrb/tbnz + tail) |
| 7 | 0x1fa40 | → FUN_00050ef0 **CompleteMovie/encoder config** (below) |
| 8 | 0x1fa90 | → FUN_000500f0 |
| 9 | 0x1fad0 | session open: rejects anything but (0x200,{1,2}) → FUN_000514a0 |
| 10 | 0x1fb70 | rejects size!=0x200/0x100, sub!=1 (banded) |
| 11-12 | 0x1fc20/0x1fc90 | state-gate getters (same thunk shape) |

### caps2:r (12 methods, vtable 0x14dec0+0x20)

| Slot | Offset | Behavior |
|---|---|---|
| 4 | 0x1fd50 | → FUN_000298c0 (fixed 0x30-byte struct copy from cmif buffer) |
| 5 | 0x1fda0 | → FUN_0002a710 **the big one — recording frame pipeline** |
| 6 | 0x1fe00 | → FUN_0002bc60 reset |
| 7 | 0x1fe30 | → FUN_0002c140 (event/data get, fixed 16B out) |
| 8 | 0x1feb0 | → FUN_0002c330 (fixed 0x30 struct) |
| 9 | 0x1fef0 | state gate + FUN_0003b9e0 |
| 10 | 0x1ff60 | → FUN_0002c4f0 (fixed 0x38 struct) |
| 11 | 0x1fff0 | → FUN_0002d260 (fixed 16B out) |
| 12-15 | 0x1ffb0/0x20070/0x20100 | state-gate thunks; 0x20100 → FUN_0003d500 |

### Memory-safety findings

**F1 — caps2:r slot 5 (FUN_0002a710) client-buffer memcpy: BOUNDED.**
`memcpy(heap+0x76e4022, *param_6, param_6[1])` @ **0x2aa28**: client-supplied
length explicitly capped `if (0x10000 < size) return 0x108910` @0x2ab3c
before the copy; destination is the 0x10000 recording-metadata block.
Class: **logic-only (safe)**. Weaponization: 0.

**F2 — caps2:s slot 7 (FUN_00050ef0) config validation: BANDED.** Every
field from the packed client word is range-checked before use; the only
table deref `DAT_00128660[uVar2*4]` is guarded `0xb < uVar2 → 0x108110`
(uVar2 = byte-1, so index ∈ [0,0xb]). Class: **safe**.

**F3 — session setup FUN_000514a0: ENUM-CLAMPED.** Width ids {1,2,3,4,0x100,
0x200,0x300} → fixed {0x36×0x60 ... 0x870×0xf00}; pixel-format {1,2,3,4} →
fixed multipliers; bitrate per-id constants. No client integer reaches an
allocation size un-banded. Class: **safe**.

**F4 — internal pipeline memcpy @0x2af98 (FUN_0002a710): size from GPU
fence.** `memcpy(gsv_shmem+0x3e71200, *puVar27, puVar27[2])` where
`puVar27[2]` = `*(u64*)(nvn_sync+0xc)` — the frame size written by the
**gsv4 video-encoder process** through the shared nvdrv fence (trace:
FUN_0002f400 allocator pop → FUN_00030690 SyncWaitExternal fence payload →
FUN_00032a60/32bf0 ring publish). Destination is a pool block (0x6000/0x10000
region +0x3e6b200/+0x3e71200). **No guard between the fence-reported size
and the destination block capacity in this function.** Class: potential
oob-write, but the attacker model required = control of gsv4/nvdrv fence
payloads (GPU-side), i.e. NOT reachable from raw HTTP/USB/IPC bytes.
Reachability from external input: **none on this firmware**. Weaponization
score: 1 (internal-correctness bug at best; a compromised gsv4 would already
be a stronger primitive than this memcpy).

**F5 — all other IPC paths**: fixed-size struct copies (0x30/0x38/0x100)
into .bss/globals with cmif-declared sizes; no variable-length client
buffers on any caps2 method (no buffer flags beyond fixed 0x100
transfer-storage at 0x24d88-adjacent FUN_00024940 — internal event pump,
nn::os multiwait, count 0x40 vs local_168[66]: bounded).

## 4. S1 cross-reference (what S2 inherited vs dropped)

| S1 artifact | S2 23.0.0 status |
|---|---|
| bsd:s server-mode sockets in photoViewer | **dropped** (bsd:a only) |
| lp2p:sys (WiFi-Direct group owner/AP) | **dropped** (lp2p:m monitor only) |
| RomFs /http/ web UI | **absent** (23.0.0 wiki: lyt/message/sound only) |
| 192.168.0.1 / data.json / img/ strings | **zero hits dump-wide** |
| `switch_`+11 SSID, 8-char WPA2 pass | **zero hits dump-wide** |
| capmtp USB MTP lane | **present and already audited** (docs/MTP-AUDIT.md + usbsys AUDIT-NOTES.md) |
| capsrv album services | present as capsrv (S1-lineage) + capsrv2 (recording, new) |

Nothing "S1-era suspicious" was inherited into the S2 network path because
the S2 network path for this feature does not exist.

## 5. Live-probe design

**Lane A (the mission's probes) — now predicted-EMPTY; run once to close it:**
If Album → Send to Smartphone is invoked on this firmware and no AP appears
(`airport -s` shows no new SSID; no DHCP offer), the lane is confirmed dead
on-device and no HTTP probes apply. If an AP *does* appear (feature restored
in a newer firmware than our dump — our dump is 23.0.0), fire the S1 battery
below (python3 + curl from the Mac after joining):

| # | Request | Oracle |
|---|---|---|
| P1 | `curl -v http://192.168.0.1/data.json` | 200 + JSON (baseline); compare S1 field set — S2 field diffs reveal new parsers |
| P2 | `GET /data.json` with `Range: bytes=0-4294967295` | non-206/conn-reset = length handling; hang = int-truncation in range math |
| P3 | `GET /img/../../../../proc/self/cmdline` variants + `%2e%2e%2f` overlong (8192×`../`) | any non-404 → path normalization bug (the fs Path::Normalize class); conn-reset = parser crash |
| P4 | `GET /img/<8000-char name>` | slow-loris or reset = fixed-size copy without bound |
| P5 | `Content-Length: 18446744073709551615` POST to `/` | wrap/allocation path |
| P6 | raw `GET\r\n\r\n` garbage verbs, `GET / HTTP/9.9`, header with no colon, 63KB single header | teardown/crash = header parser edge |
| P7 | rapid 2 parallel connections (server documented single-request) | race on the one-request state machine |
| P8 | QR2 URL mutation — if S2 QR encodes a token, request `/data.json?token=...` with 1-char perturbations ×8 + timing | response-time delta on token compare = early-exit token check (byte-at-a-time oracle) |

**Lane B (what replaces it on S2)**: the USB MTP lane (already running —
docs/MTP-AUDIT.md live corpus v3; cancel-injection 2-byte repro confirmed).

## 6. Verdict

- **capsrv2 is not the smartphone server and cannot be one** (no network
  services in NPDM; it's the S2 recording/mux service).
- **The S1-style Send-to-Smartphone HTTP attack surface is absent from
  fw 23.0.0 JPN entirely** — proven by exhaustive string/byte sweep of every
  module + applet, NPDM SAC analysis (no bsd:s / lp2p:sys / AP-capable
  service granted to the Album applet), and code-level confirmation that the
  only HTTP machinery in the Album applet is libcurl 7.64.1 + nghttp2 as a
  *client*.
- **capsrv2's real IPC surface is clean**: 21 methods, all client inputs
  enum-banded or size-capped (0x10000 guard @0x2ab3c); one unguarded
  internal memcpy (0x2af98) whose size comes from the GPU fence — internal
  correctness issue, externally unreachable, score 1/5.
- **Lane verdict: NOT weaponizable on this firmware.** Where corruption
  could live if the lane returns: the `/img/` filename→fs path (P3) and any
  new S2 endpoint's parser — probe set ready above. Recommend demoting
  this lane in EXTERNAL-SURFACES.md and re-checking on next firmware dump
  (strings sweep takes minutes: `for f in *.bin: count 192.168.0.1/data.json/WIFI:S:`).

## Artifacts

- /tmp/bjbresearch/caps2work/ — album.bin/album.elf (15.6MB, Ghidra proj
  alb), capsrv2.bin→capsrv2.elf (Ghidra proj caps2), decompile dumps
  (decomp_*.txt), svc_funcs.txt, memcpy_sites.txt, mkelf scripts
- Title dirs: `/Users/dviros/Downloads/FW dump Switch2 JPN/0400000000000071`
  (capsrv2), `.../0400000000000022` (capsrv), `.../040000000000001b`
  (capmtp), `.../040000000000100d` (Album)
