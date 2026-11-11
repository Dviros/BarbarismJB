# WebKit analysis of the Switch 2 browser stack — fw 23.0.1 dump

Date: 2026-11-10. Input: the same untrusted ns2jb dump as
`STATIC-VALIDATION.md` (`<FW_DUMP_ROOT>`,
90 captured titles, session `switch2-Jo141G`). Everything here was derived
read-only: no dump binary was executed; LZ4 decompressions and scratch
tooling stayed in `/tmp` outside the repo. Companion tool:
`tools/webkit_version.py` (stdlib-only, `--self-test`, reproduces §2, §3 and
the segment layout of every module cited here).

Offset conventions: `file+X` = byte offset in the dump file; `text+X` /
`ro+X` = offset inside the **decompressed** `.text`/`.ro` segment of an NSO;
`mod+X` = offset in the flat decompressed module image (text at 0). NSO
segment locations and sizes are printed by the tool (`python3 -I
tools/webkit_version.py <nso>`). Disassembly was done with rizin 0.9.1
(`/opt/homebrew/bin/rizin`, native NSO0 support); Ghidra was not needed.

---

## 1. Title map — every browser-adjacent title

### 1.1 System-program / library titles

| Title | NPDM META name | Files (dump) | Role |
|---|---|---|---|
| `0x040000000000085d` | `BrowserCoreDll-` | `wkc0..wkc4`, `main.npdm` (1 124 B), `code-info.bin` (420 B) | the shared WebKit engine **library** title (loaded into web applets) |
| `0x040000000000005d` | **absent** | — | see §1.4 |

`0x85d/main.npdm` (sha256 `0d115265…`, parsed with `tools/npdm.py -v`):
main thread priority 44 / core 0 / stack 0x100000, flags0 `0x27`
(AddrSpace64Bit39), ACID RSA-4096 production `memory_region=2`, program-id
range pinned to `0x040000000000085d`. **FAC = 0, SAC = none, syscalls = 0**
— a pure CodeFS library provider; it never runs as a process.

The five NSOs (`NSO0`, flags `0x7f`, LZ4 block-compressed; layout in §1.2):

| File | file size | decompressed image | content (from rodata/symbols) |
|---|---|---|---|
| `wkc0` | 5 702 514 | 0x91a4e8 (9.5 MB) | `oss_wkc` — OpenSSL **3.5.7** (`wkc0.ro+0xf48a1` "OpenSSL 3.5.7 9 Jun 2026"), cURL (`wkc_curl_*` ro+0xe1a35…), libxml2 (ro+0xe65c7), libpng, nghttp2, brotli, zlib, SQLite |
| `wkc1` | 345 207 | 0x80200 | `cairo_wkc` — Cairo 2D |
| `wkc2` | 557 792 | 0x1004b0 | `peer_wkc` — platform "peer" layer: memory/thread/net/file/draw/media callbacks (`wkc*Peer` C exports, §4.2) |
| `wkc3` | 19 446 846 | 0x25a40b1 (39.5 MB) | `webkit_wkc` — WebKit + JavaScriptCore + the WKC API (§2) |
| `wkc4` | 233 668 | 0x60004 | `libfont` |

### 1.2 Switch-2 NSO0 header layout (needed to read anything)

The fw-23 dump's NSOs do **not** use the Switch-1 header layout. Verified
against rizin 0.9.1 on `wkc4`/`wkc3` and byte-consistency (file sizes sum
exactly): segment triples at **0x10 (text) / 0x20 (ro) / 0x30 (data)** as
`{file_off, loc, decomp_size}`, and the on-disk (compressed) sizes at
**0x60/0x64/0x68** (`text_file_size + ro_file_size + data_file_size ==
file size`; e.g. wkc3: `0xe318f1 + 0x433e88 + 0x263ba == 0x128bc3e`).
`tools/validate_ipc.py`'s older reading happens to work only because its
slices over-read harmlessly. `tools/webkit_version.py` implements the
correct decode; MOD0/dynamic section sits in `.data` (wkc3: dyn at
`mod+0x25807a0`).

### 1.3 The 0x10xx libapplets (all 23, NPDM META names)

`System`(1000), `Pin`(1001), `Controller`(1003), `Viewer`(1005),
`Account`(1007), `TextEditor`(1008), `MiiEdit`(1009), `Overlay`(100c),
`Album`(100d), `Setting`(100e), **`LibAppletOff`(100f, + subsdk0–4)**,
`MyPage`(1013), `Maintenance`(1015), `NxSwkbd`(1041), **`SystemWeb`(1042)**,
**`LibAppletWeb`(1043)**, `News`(1045), `Splay`(1048),
**`LibAppletOff`(104b)**, `QuestSA`(104c), `Hdr`(104d), `Vgc`(1054).

Which of these actually host WebKit (dynsym import census; method §4.1):

| Title | WKC:: imports in `main` | engine binding |
|---|---|---|
| `0x1042` SystemWeb | 319 (+42 JSC C-API) | dynamic — `BrowserCoreDll` NSOs |
| `0x1043` LibAppletWeb | 319 (+42) | dynamic — `BrowserCoreDll` NSOs |
| `0x104b` LibAppletOff | 319 (+42) | dynamic — `BrowserCoreDll` NSOs |
| `0x100f` LibAppletOff | 292 | **static** — engine embedded as `subsdk0–4` |
| 1041, 1045, 1048, 104c, 104d, 1054 | 0 | not browser hosts |

- `0x100f` is `LibraryAppletOfflineWeb` (plus variants `OfflineWebSystem`,
  `OfflineWebApp_0`, `OfflineWebApp_3` — AppletId strings at
  `100f/main.ro`), and its ExeFS carries the *whole engine again* as
  cruiser-sample builds: `subsdk0 = cairo_wkc.nss`, `subsdk1 = libfont.nss`,
  `subsdk2 = oss_wkc.nss`, `subsdk3 = peer_wkc.nss`, `subsdk4 =
  webkit_wkc.nss` (build strings `F:\BrowserEngineRelease\Source\
  applications\cruiser_sample\build\Ounce64\Release\*.nss` in each subsdk
  rodata; subsdk4 = 15.6 MB text, exports 2 424 WKC:: symbols the applet
  resolves against). It also still imports 292 WKC:: symbols in `main` —
  the static copy is the one exported to it; either way the engine runs
  in-process. Its embedded copy self-identifies as WKC customer release
  **0.12.2** (`webkit_version.py` on `100f/subsdk4`; string at subsdk4
  mod+0x12cec18) vs the shared Dll's 3.12.11 — the cruiser_sample build
  is versioned separately from the shared BrowserCoreDll.
- **Captive portal**: there is **no separate wifiWebAuth title on Switch
  2**. The captive-portal login lives inside `LibAppletWeb` (0x1043):
  strings `WifiWebApplet`-family — `1043/main.ro+0xe0e59
  "WifiWebAuthApplet"`, `+0x104d0a "checkForWifiWebAuth"`,
  `checkForNonWifiWebAuth` — i.e. the Switch-1 `wifiWebAuth` applet
  became a launch mode of LibAppletWeb.

### 1.4 Title `0x040000000000005d` — premise correction

The mission brief says 0x5d "also exists". It does not: no directory, no
`firmware-dump.json` entry, and no key with low bits `0x5d` among the 90
NCM ContentMetaKeys in `ncm-system-programs.bin` (checked; max id present
is `0x040000000000b240`). The nearest titles are `0x52 cmptldr` and
`0x62 gc`. **INCONCLUSIVE / brief error** — most likely a truncation of
`0x85d` itself.

---

## 2. WebKit vintage

### 2.1 Version markers (exact evidence)

- **WKC engine version = `3.12.11`**: export
  `_ZN3WKC28GetWKCCustomerReleaseVersionEv` at `wkc3 text+0x1942b68`
  (rizin: `adrp x0, 0x9eca000; add x0, x0, 0x6bc; ret`) → string at
  `wkc3 mod+0x1eca6bc` (ro+0x5726bc): `"3.12.11"`. This is Nintendo's
  WKC/NetFront-lineage product version, not an upstream WebKit number.
- **Build provenance**: hundreds of assert paths
  `F:/BrowserEngineRelease/Source/webkit/JavaScriptCore/...`,
  `Source/webkit/WebCore/...` (first seen `wkc3.ro+0x525c02`) and the
  applet shell `Q:/JetCruiser/Daily/ReleaseBuild/cruiser-code/product/
  src/...` (e.g. `1043/main.ro+0xe0661`). "JetCruiser" is the browser
  applet product; the WKC + `wkc*Peer` API set is the Access NetFront
  Browser customization lineage (same `WKCWebKit*` API family as the
  Switch-1 browser).
- **User-Agent (gold, partially)**: composed at runtime — format strings
  in the applets: `1043/main.ro+0x117595 "Mozilla/5.0 "`,
  `+0x101f72 "AppleWebKit/%s (KHTML, like Gecko) "`,
  `+0x105738 "NintendoBrowser/%d.%d.%d.%s"` (SystemWeb: `1042/main.ro`
  +0x118156 / +0x1025b0 / +0x106024, plus `+0x1127ff "NintendoBrowser"`).
  The `%s`/`%d` fills are runtime values (system version + engine
  constants) — exact runtime UA **INCONCLUSIVE statically**; on-console
  `navigator.userAgent` answers it in one run.
- **Crypto vintage**: `OpenSSL 3.5.7 9 Jun 2026` (`wkc0.ro+0xf48a1`) —
  the engine was rebuilt against a June-2026 OpenSSL. Bounds the *build*
  date, not the WebKit base.

### 2.2 Upstream base: WebKitGTK 2.39.1 window (Oct–Nov 2022)

Method: JSC's runtime-option table is embedded verbatim in rodata
(`useXxx` strings, 97 in wkc3). I diffed that set against upstream
`Source/JavaScriptCore/runtime/OptionsList.h` at tagged releases
(raw.githubusercontent.com, WebKitGTK/WPE tags):

- Every `useXxx` option in wkc3 already exists upstream at
  **`webkitgtk-2.39.1`** (Oct 2022): includes `useTemporal`,
  `useShadowRealm`, `useDataICSharing`, `useWasmLLInt{Prologue,Loop,
  Epilogue}OSR`, `useWebAssemblyTypedFunctionReferences`.
- wkc3 **still has 5 options that upstream removed in `webkitgtk-2.39.2`**
  (Nov–Dec 2022): `useArrayFindLastMethod`, `useAtMethod`, `useHasOwn`,
  `useIntlEnumeration`, `useWebAssemblyExceptions` (and
  `useFastTLSForWasmContext`, removed by 2.39.4).
- wkc3 has **zero** options added upstream from `webkitgtk-2.39.2` onward —
  notably no `useWasmIPInt*` (the IPInt rename), no `useFloat16Array`,
  no `useArrayFromAsync`, no `useResizableArrayBuffer`, no
  `useAtomicsWaitAsync`.

Conclusion: the fork point is the **WebKitGTK 2.39.1 development window,
Oct–Nov 2022** — the source that became 2.40 / Safari 16.4 (engine-era
614.x). Eight 2.39.1-present options are absent from wkc3
(`useWebAssemblyGC`, `useImportAssertion`, `useChangeArrayByCopyMethods`,
`useGlobalGC`, `useDataICInFTL`, `useLLIntICs`, `useArrayGroupMethod`,
`useWebAssemblyBranchHints`) — either Nintendo feature-defines or a
slightly earlier branch point; does not move the window.
`tools/webkit_version.py` prints the marker list for reproduction.

Corroborating JS/WebCore feature census (strings in wkc3.ro): Temporal
implemented in depth (108 strings; `Temporal.Now`, `Temporal.ZonedDateTime`,
`Temporal.Duration.prototype.round…`, and
`ro+0x539b60 "FIXME: Temporal.Instant.toString({timeZone}) not implemented
yet"`); ShadowRealm implemented (`%ShadowRealm%.evaluate` builtin JS at
`ro+0x5ff0f0`…); `reportError` present (`ro+0x5675e8`, landed upstream
late 2022); WebGPU modules present but pre-shipping shape
(`WebCore/Modules/WebGPU/GPU*` + `PAL::WebGPU::convertToBacking` symbols).
Absent: Float16Array, Uint8Array.fromBase64, RegExp.escape, iterator
helpers, Array.fromAsync, CompressionStream — all post-2022. Consistent.

### 2.3 CVE window (base 2022-11 ± 2 months → firmware 23.0.1, 2026-10)

Four years of upstream WebKit/JSC security fixes are not in this engine.
Candidate classes only — **no exploitability is claimed**; each would need
the Nintendo fork diffed to confirm the bug survived (unknown, §5):

- In-the-wild WebKit chain CVEs from 2023 on, i.e. bugs that existed in a
  late-2022 tree: CVE-2023-23529 (JSC type confusion, ITW Feb 2023),
  CVE-2023-32435 / CVE-2023-32439 (Operation Triangulation memory
  corruption / type confusion, fixed Safari 16.4/16.5.1),
  CVE-2023-41074 (JSC integer overflow ITW, Safari 17),
  CVE-2023-41983 (JSC, Safari 17.1),
  CVE-2024-44308 (JSC RCE ITW, Safari 18.1 — public exploit analysis
  exists, including PAC-era mitigations),
  CVE-2025-31200 / CVE-2025-43529 / CVE-2025-14174 / CVE-2025-43541
  (WebKit memory corruption / type confusion ITW 2025–2026).
  // correction: CVE-2025-31200 is a CoreAudio bug, not WebKit (the WebKit
  // sibling of that release is CVE-2025-31201) — see WEBKIT-NDAYS.md §2.1 #9.
- Bug-class families for a 2.39-era JSC: DFG/FTL miscompilation and
  escape-analysis bugs (structure/butterfly corruption → fake-object
  primitives — the JSC analog of the V8 "TheHole / Map corruption" class
  the Civ 7 host uses; "TheHole" itself is V8-specific and does not exist
  in JSC), array-storage OOB, Intl/RegExp (Yarr) issues, and the
  then-experimental surfaces this build enables by default strings:
  Temporal, ShadowRealm, Wasm GC / typed function references
  (`useWebAssemblyGC`-era code compiled in), Wasm LLInt.
- Also in-surface but lower-level: cURL + OpenSSL 3.5.7 network stack
  (`wkc0`), libxml2/png/jpeg decoders (parser pre-auth surface via any
  content the applet fetches).

Sources: Apple security advisories / NVD for the CVEs above; Exodus Intel
"CVE-2024-44308" writeup (2025-08); Google TAG 2024 zero-day trends;
Kaspersky Operation Triangulation series. (Links in §6.)

---

## 3. Hardening posture

### 3.1 PAC — everywhere, B-key

Byte-pattern census over decompressed `.text` (encodings verified with
`rz-asm`; counts/MB by `tools/webkit_version.py`):

| module | text MB | pacibsp/MB | retab/MB | autibsp/MB | bti.* total |
|---|---|---|---|---|---|
| wkc3 webkit | 26.57 | 2 921 (77 624) | 2 432 (64 631) | 1 085 (28 831) | **0** |
| wkc0 oss | 5.91 | 2 276 | 1 899 | 747 | 0 |
| wkc1 cairo | 0.39 | 2 257 | 1 837 | 932 | 0 |
| wkc2 peer | 0.10 | 2 672 | 2 133 | 843 | 0 |
| wkc4 libfont | 0.29 | 865 | 1 028 | 219 | 0 |
| 1042 main | 9.29 | 2 382 | 2 190 | 727 | 0 |
| 1043 main | 9.28 | 2 382 | 2 190 | 728 | 0 |
| 100f main | 8.95 | 2 420 | 2 225 | 770 | 0 |
| 100f subsdk4 (embedded webkit) | 15.56 | 2 647 | 2 169 | 1 377 | 0 |
| 104b main | 9.27 | 2 382 | 2 189 | 727 | 0 |

Zero `paciasp`/`autiasp`/A-key sites; the scheme is uniformly
`pacibsp` prologue (sample: rizin @ `0x08000000+0x1916664`
`RemoteAutomationTargetWKC::browserVersion`, first insn `pacibsp`) with
`retab` (or `autibsp; ret`) epilogues. Implications:

- The browser stack (and the whole dump's userland) is compiled
  `-mbranch-protection=pac-ret` (B-key) and *executes* on Switch 2 —
  empirically the CPU implements FEAT_PAC (ARMv8.3+).
- **Return-address ROP is PAC-gated**: a naive ret-chain faults on
  AUTIB. BUT there is **no branch-target authentication anywhere** and
  **no BTI** (§3.2): `br xN`/`blr xN` function-pointer calls are entirely
  unauthenticated — call-oriented programming (driving existing exported
  functions with controlled args) is unconstrained by PAC.

### 3.2 BTI — absent

`bti.c` / `bti.j` / `bti.jc` encodings: **zero in every module** (table
above). No indirect-branch landing-pad enforcement.

### 3.3 XOM / misc loader flags — INCONCLUSIVE from this dump

`code-info.bin` (0x1a4 B) is opaque apart from the trailing u32 = 1 at
0x1a0 (the "signed" flag already documented in `STATIC-VALIDATION.md`
§10); no decodable XOM/execute-only bit. NPDM fields decode by `npdm.py`
show nothing XOM-shaped (flags0 `0x27`, ACID memory_region 1 (applets) /
2 (0x85d)). Note the engine's own W^X discipline (§3.5) means code pages
are RX except during JIT writes anyway; XOM for a JIT-using process would
be contradictory.

### 3.4 RELRO / CFI

Dynamic tags (MOD0 → `.data`): `DT_FLAGS = 0x8` (BIND_NOW) and
`DT_FLAGS_1 = 0x1` (NOW) on wkc3, wkc0, wkc2 and the applet `main`s
(e.g. wkc3 dyn at `mod+0x25807a0`) — eager binding; with Horizon's RELRO
application the GOT is read-only after load. No `__cfi*` symbols in any
extracted dynsym (10 modules checked) — no LTO CFI.

### 3.5 JIT — CORRECTED VERDICT: NO JIT. JSC runs on C_LOOP

> **2026-11-11 correction.** The original verdict below ("JIT-enabled
> build: CONFIRMED") was **wrong**. The Nintendo GPL source archive
> (`NS2_23.0.0.zip`, sha256 `a2bcdfb7…0f90`, `vendor/nintendo-oss/`)
> ships the exact browser source (`WKC_3.12.11` / `webkit_3.12.11`,
> WKC_CUSTOMER_RELEASE_VERSION "3.12.11", WKC_WEBKIT_VERSION "613.0" —
> matches the applet UA). Its `WKC_3.12.11/WTF/wtf/WKC/FeatureDefinesWKC.h`
> states:
> `ENABLE_JIT 0` (line 108), `ENABLE_DFG_JIT 0` (85), `ENABLE_FTL_JIT 0`
> (92), `ENABLE_C_LOOP 1` (76), `ENABLE_WEBASSEMBLY 0` (156),
> `ENABLE_WEBGL 0` / `ENABLE_WEBGL2 0` (160/161), `ENABLE_CSS_SELECTOR_JIT 0`.
> It is wired in unconditionally: `PlatformEnable.h:104` includes it
> BEFORE the `#if !defined(ENABLE_JIT)` defaults at :583, so the arm64
> default-enable never fires.

Why every original evidence pillar was a **dead letter** (reinterpreted):

1. **Option strings/defaults in `wkc3.ro`** (useJIT/useFTLJIT=true etc.):
   `OptionsList.h` declares all JIT rows **unconditionally**; defaults are
   literal `true`, and `jitEnabledByDefault()` in this fork is NOT
   `#if ENABLE(JIT)`-gated — it is `return is32Bit() || isAddress64Bit()`
   (`runtime/Options.cpp:240`) = true on arm64 in ANY build. The decoded
   `useJIT=true`/`useFTLJIT=true` values compile into a C_LOOP build; their
   consumers are `#if ENABLE(JIT)`-compiled-out. Hardware-confirmed analog:
   `useWebAssembly` also decodes `true` yet `WebAssembly` is undefined
   on-device (buberlo, tasenjo80).
2. **"jump islands / ExecutableAllocator" string** (+0x55f3f0): it is the
   `useRandomizingExecutableIslandAllocation` option *description*
   (`OptionsList.h:520`) — option-table rodata, present in every build.
3. **wkc2 exec-memory peer exports** (`wkcMemorySetExecutablePeer` etc.):
   the WKC peer ABI is fixed surface; the applet-side implementations are
   **bare `ret` stubs** (§ dump analysis) — a host-level DENY. A browser
   that works on hardware while these stubs return nothing proves the
   engine never performs real JIT allocation through them.
4. **`WKC::Heap::GetJSJITCodePageAllocatedBytes`**: WKC glue accounting
   (fixed ABI), the ONLY JIT-flavored symbol among wkc3's 4,878 dynsyms —
   no FTL/B3/Baseline machinery is exported or present.
5. **NPDM svc 0x48/0x49/0x80**: kernel permission grants (template copy
   / wkc2 glue use), not engine code presence.

Corroborating external evidence: wontfix (Aug 2025, fw 5.x behavioral
analysis) concluded no JIT; tasenjo80's roadmap models the applet as
no-JIT; pepsipu's XOM/PAC/CFI writeup frames WebKit escalation as
data-only.

**Verdict (final): the Switch 2 web applets run JSC on the C_LOOP
interpreter. No JIT tiers, no WebAssembly, no WebGL (all compile-time).
Consequences: (a) the JIT-page escalation path (§5.1) is DEAD; all
escalation from in-applet ARW is data-only; (b) n-day triage must EXCLUDE
JIT-tier CVEs (FTL/DFG/B3 miscompiles) and focus on C_LOOP/LLInt,
parser/binder, runtime object model, WebCore DOM/CSS, WKC glue/peers;
(c) behavioral miscompile probes (probe-32439) are only meaningful if the
bug is interpreter-reachable — re-triage each candidate against the fix
commit in this exact source tree (new capability: the tree is the fork
point, so any post-Oct-2022 fix can be diffed mechanically).**

---

## 4. Attack surface

### 4.1 Binding graph (dynsym, extracted via MOD0 → DT_SYMTAB/STRTAB)

```
SystemWeb/LibAppletWeb/LibAppletOff(104b) main   (294 exports, 630 imports)
  ├─ 319 × WKC:: symbols  ──► wkc3 webkit_wkc   (3609 exports: 2424 WKC::,
  │                           110 JSC C-API, WKC internals)
  └─ 42 × JSC C-API       ──► wkc3   (JSGlobalContextCreateInGroup,
                                      JSObjectMakeFunctionWithCallback,
                                      JSObjectGetTypedArrayBytesPtr, …)
wkc3 (1269 imports) ──► wkc2 peer (427 × wkc*Peer)  and  wkc0 oss
                        (OpenSSL ASN1_*/BIO_*/SSL_*, cURL, libxml2 …)
wkc2 peer (700 exports) ──► libc/nnsys (fclose/fopen/gettimeofday/…)
```

The applet registers the page-facing `nx.*` bridge as native callbacks
(`JSObjectMakeFunctionWithCallback` among its imports; JS snippet
`window.nx.dispatchEvent` at `1043/main.ro+0xeab33`). The JSC C API being
*exported* by wkc3 (e.g. `JSGlobalContextCreateInGroup` at
`wkc3 text+0x899eb0`) means an in-process payload can mint JS contexts
without touching the browser stack's own state.

### 4.2 URL / allowlist handling (LibAppletWeb rodata)

- Policy engine is regex-based: `DivideRegexUrlListIntoAllowListAndDenyList`
  (`1043/main.ro+0xeedbe`), `allowList.isValid() || denyList.isValid()`
  (+0xf0d4d), `"Server %s is blacklisted"` (+0xf1942) — the launching
  application supplies an allow/deny regex list (Switch-1 web-applet
  model) **plus** hard-coded platform regexes:
  - `+0xe5fad ^https://ec\.nintendo\.com/`
  - `+0xe61bf ^https://([0-9A-Za-z\-]+\.)*nso\.nintendo\.net(/|$)`
  - `+0xeb41e ^https://(.*\.)?accounts\.nintendo\.com$`
  - `+0xeb70c ^https://(.*\.)?(accounts\.nintendo\.com|savanna\.srv\.nintendo\.net|nso\.nintendo\.net)$`
  - `+0xeef7a ^https://([0-9A-Za-z\-]+\.)*accounts\.nintendoswitch\.com\.cn(/|$)`
  - `+0xf0c61 ^https://([0-9A-Za-z\-]+\.)+nso\.nintendo\.net$`
  - `RemoveEcJumpSystemSchemeBaseUrl` (+0xed1d0)
- Internal/virtual origins: `https://webapplet` (+0xf1512),
  `shareddata:/webdatabase` (+0xeab1b), `sd:/NXWebApplet/` (+0x10cd30 —
  an SD-card path reference, worth a runtime look),
  `https://web-%.znc.srv.nintendo.net/lobby/` (SystemWeb
  `1042/main.ro+0x1022e7` area).
- Scheme literals: `http://` (+0xf6357), `https://`, `file://` (+0xf406f),
  `about:`, `data:` handling in engine.

### 4.3 TLS / certificates

- Transport = cURL + OpenSSL 3.5.7 inside `wkc0`, driven from WebKit's
  ResourceHandle (`_ZNK3WKC14ResourceHandle22SSLVerifyOpenSSLResultEv`
  `1043/main.ro+0xdde2a`, `SSLVerifycURLResult` +0xdde2a region).
- Trust store: PEM bundles `browser/RootCaEtc.pem` (+0x102d51) and
  `browser/RootCaSdkAdditional.pem` (+0x104c0b);
  `WKCWebKitSSLRegisterRootCAByDER` (+0xdb6d2) lets the host add CAs.
- Online-revocation toggle: `WKCPrefs::setSSLEnableOnlineCertChecks`
  (+0xdb731). Client certificates: `SSLClientCertDeleteAll`
  (`wkc3.ro+0x523a4f` region exports `SSLRegisterBlackCert`,
  `SSLUnregisterClientCert`…). Certificate-error **user dialog**
  (`DialogCertificateError.cpp` path +0xe0661) — warning-accept flow
  exists, standard for captive portals.
- **No pinning indicators found** (no pin/HPKP-like strings in any
  module) — pinning: none evident.

### 4.4 NPDM SAC — what JS-in-applet reaches

Identical 48-svc kernel caps for 1042/1043 (incl. 0x48/0x49/0x80, §3.5);
`LibAppletWeb` client SAC (33 services): `acc:u1, adraw:a, appletAE,
aud:u, auddmg:u, audsmx:u, banana, bsd:a, csrng, erpt:c, fatal:u,
fsp-srv, hid, hid:sys, htc, htc:tenv, imf, ldn:m, lm, lp2p:m, nifm:s,
ns:vm, ns:web, nsd:u, ntc, pctl, pl:u, prepo:s, set, set:sys, sfdnsres,
ssl, time:u`. `SystemWeb` adds `caps:a, caps:ss, friend:m, mnpp:web,
news:c, nim:shp, ns:sweb, spch:a`.

That is: **raw sockets (`bsd:a`), DNS (`sfdnsres`), TLS (`ssl`), network
config (`nifm:s`), filesystem client (`fsp-srv`), account, audio, HID,
capture, applet lifecycle** — a far richer service surface than `ro`'s
three (STATIC-VALIDATION §4.3), and sockets are exactly what the M5 shell
needs. No `sm:` arbitrary-open (kernel enforces SAC) and no `ldr:`.

---

## 5. Verdict for a `host: webkit` provider

**What a WebKit entry buys.** JS execution in a *single-process* web
applet — the engine NSOs (or the embedded .nss copies in 0x100f) are
mapped into the applet itself, networking (cURL/OpenSSL) runs in the same
process, and there is no separate sandboxed renderer. A JSC memory-corruption
bug therefore lands directly in a process whose SAC includes `bsd:a`,
`sfdnsres`, `ssl`, `nifm:s`, `fsp-srv` — i.e. JS ARW in LibAppletWeb is a
networked, fs-capable userland foothold *without* needing the fs chain at
all (though it gives no kernel step by itself).

**Most reachable vectors** (ranked, evidence-based):
1. `LibAppletWeb` (0x1043) — launched by any game (signed publishers) or
   by the system for **captive-portal login** (`WifiWebAuthApplet`,
   `checkForWifiWebAuth`): content is attacker-influenced on networks the
   console joins; the certificate-warning dialog path shows hostile-TLS
   is an anticipated state.
2. `SystemWeb` (0x1042) — system-initiated pages (news, error docs,
   `web-%.znc.srv.nintendo.net` lobby URLs).
3. `0x100f/0x104b` offline web — local content only, engine identical
   vintage (subsdk4 fingerprint matches), same JIT plumbing.

**ARW → native code, documented-by-evidence path** (in that process):
- No need to defeat PAC for calls: `br`/`blr` are unauthenticated (§3.1)
  and the process exports clean C call surfaces — wkc3's JSC C API
  (`JSGlobalContextCreateInGroup` @ `wkc3 text+0x899eb0`,
  `JSObjectMakeFunctionWithCallback`, …) and wkc2's `wkcMemory*Peer`
  (`wkcMemoryExecutableMallocPeer` @ `wkc2 text+0xbc44`,
  `wkcMemorySetExecutablePeer` @ +0xa2d0, `wkcMemoryCacheFlushPeer` @
  +0xa2d4). ARW can drive those directly (call-oriented), allocate the
  JIT executable region, write shellcode while RW, flip to X, flush
  icache — native execution without any ROP chain, hence PAC-in-the-attacksurface
  matters only for return-address hijacking, which this path avoids.
- The svc-permitting NPDM (0x48/0x49/0x80) makes the peer's
  executable-memory API kernel-legal for these applets (§3.5).

**Top 3 unknowns** (each blocks a claim above):
1. **Runtime JIT state**: is JIT enabled by default for page JS, and how
   exactly does `wkcMemorySetExecutablePeer` map (svc 0x48/0x49 pages?
   JIT-island carve-out?) — one console run with `JSC_dumpOptions`-equivalent
   or reading the executable region via QUERY answers it.
2. **Fork divergence**: how far the Nintendo 2.39.1-window branch drifted
   from upstream (backported security fixes? WKC-local changes to JSC
   internals?). Option-census dates the fork, not the patch level; only a
   real diff against an upstream 2.39-era build (or per-CVE binary
   checks) closes §2.3.
3. **Entry enforcement**: what the launch-arg allowlist actually enforces
   for LibAppletWeb (game-supplied URLs; captive-portal mode reachability
   and whether warning-accept is enough to reach arbitrary JS), plus the
   runtime UA strings (`AppleWebKit/%s` fill) — all INCONCLUSIVE
   statically.

---

## 6. Reproduction & sources

```sh
python3 -I tools/webkit_version.py --self-test
python3 -I tools/webkit_version.py '<dump>/040000000000085d/wkc3'
python3 -I tools/webkit_version.py --all '<dump dir>'
python3 -I tools/npdm.py '<dump>/0400000000001043/main.npdm' -v
# segment tables / strings cited above:
strings -a -t x <decompressed .ro>   # via webkit_version.py decode
/opt/homebrew/bin/rizin -q -c 'e asm.arch=arm; e asm.bits=64; pd 8 @ 0x08000000+0x1916664' \
  '<dump>/040000000000085d/wkc3'
```

Upstream option fingerprint source (fetched 2026-11-10):
[`OptionsList.h` at tag `webkitgtk-2.39.1`](https://raw.githubusercontent.com/WebKit/WebKit/webkitgtk-2.39.1/Source/JavaScriptCore/runtime/OptionsList.h)
(and tags 2.38.0, 2.39.2, 2.40.0 … 2.50.0 at the same path; 2.36 404s).

CVE / ITW references for §2.3:

- NVD: [CVE-2023-23529](https://nvd.nist.gov/vuln/detail/cve-2023-23529),
  [CVE-2023-32435](https://nvd.nist.gov/vuln/detail/cve-2023-32435),
  [CVE-2023-41074](https://nvd.nist.gov/vuln/detail/cve-2023-41074),
  [CVE-2023-32409](https://nvd.nist.gov/vuln/detail/cve-2023-32409)
- Apple advisories: [iOS 17 / Safari 17](https://support.apple.com/en-us/120949),
  [Safari 17.1](https://support.apple.com/en-ke/109049),
  [Safari 26.2 (CVE-2025-43541)](https://support.apple.com/en-us/125892)
- Kaspersky, [Operation Triangulation](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669)
- Exodus Intel, [CVE-2024-44308 analysis](https://blog.exodusintel.com/2025/08/04/oops-safari-i-think-you-spilled-something) (2025-08-04)
- Google TAG, [2024 zero-day trends](https://cloud.google.com/blog/topics/threat-intelligence/2024-zero-day-trends)
- Qualys wrap of the Nov-2024 Safari zero-days
  ([CVE-2024-44308/44309](https://threatprotect.qualys.com/2024/11/21/apple-releases-fixes-for-actively-exploited-zero-day-vulnerabilities-cve-2024-44308-cve-2024-44309))

Switch 1 wifiWebAuth analogy: switchbrew
[Title list](https://switchbrew.org/wiki/Title_list) (LibApplets) — the
Switch 2 title list is not indexed yet; this dump is the primary source.
