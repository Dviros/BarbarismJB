# NDAYS-V2 — corpus diff against the OSS fork-point tree (2026-11-11)

Supersedes the candidate table in `WEBKIT-NDAYS.md` §2 (which was built on
the wrong JIT-ON model and without source access). Ground truth: the
Nintendo GPL archive tree at `vendor/nintendo-oss/NS2_23.0.0/NS2_23.0.0/`
(all paths below relative to `webkit_3.12.11/`). Engine version is
**613.3.9** (Safari 16.2-branch vintage, `WebCore/Configurations/Version.xcconfig`).

## 0. Tree forensics — the tree is NOT a frozen snapshot (methodology reset)

The Dec-2022 fork carries **selective upstream roll-forward with a
per-subsystem horizon**:

- **WebCore + WTF: rolled forward to ~late-2025/early-2026.** Verified
  post-fix states locally: `DocumentFontLoader.cpp` extraction (CVE-2024-54502,
  Jan-2025 fix), `EventTargetSet = WeakHashCountedSet<Node>` (CVE-2024-54534,
  Aug-2024), `CSSParserFastPaths.cpp:1180-1197` transform length checks
  (CVE-2025-24209, Apr-2025), `HashTable.h:562,1253` `Checked<unsigned>` rehash
  (CVE-2025-43501), `AudioResamplerKernel.cpp:59-64` `safeSub` (CVE-2026-20652),
  `HRTFDatabaseLoader` ThreadSafeWeakPtr (CVE-2025-43216), and the
  CVE-2023-28205 `CloneDeserializer` MarkedVector fix family
  (`SerializedScriptValue.cpp:3934-3937`).
- **JavaScriptCore runtime/interpreter: effectively FROZEN at the fork**
  (diverged for C_LOOP): pre-Jul-2023 `MarkedVector::fill` still present,
  no 2024+ FastStringifier, no Nov-2025 Unicode length limits, no Yarr
  `/v` classes.

**Consequences:** WebCore CVEs fixed before ~late-2025 are likely already
healed (verify per-site). Every JSC-runtime CVE fixed 2023→2026 is a live
candidate unless JIT/WASM-gated. The 2023–2025 ITW stream (23222, 32435,
41993, 42917, 44308, 43529…) is almost entirely JIT/WASM/IPC-dependent and
**dead on this build** — the no-JIT config funnels exploit development at
the interpreter/runtime tier and the font pipeline.

## 1. Ranked table

| # | CVE | Component / root cause | Fix | In tree | Reachability | Notes |
|---|---|---|---|---|---|---|
| ~~1~~ | ~~CVE-2023-43000~~ (bug 255951) | ~~JSC GC: `MarkedVector::fill()` no GC-root registration~~ | 929c0df4fd46 (Jul 2023) | present — **BUT DEAD (2026-11-11 reachability re-check)**: the vulnerable `fill` at `LLIntSlowPaths.cpp:2318` is inside `handleVarargsCheckpoint`, dispatched ONLY by `llint_slow_path_checkpoint_osr_exit`, which requires `popCheckpointOSRSideState`; the sole side-state creator is `dfg/DFGOSRExit.cpp:239` — DFG compiled out ⇒ nothing ever pushes ⇒ unreachable. Plain `f(...x)` uses stack-based `varargsSetup`. | **NONE — dead code** | demoted; `varargs.html` parked |
| 1 | **CVE-2026-43715** (bug 313577) | `CSSFontFace::setStatus` re-entrant UAF | Safari 26.5.2 (Nov 2026), WSA-2026-0004 | anchor (weaponized 2x in this applet) | FULL & PROVEN | fontchain.html phase harness exists; bench yield = arb-read + arbitrary-free, controlled write NOT achieved |
| ~~3~~ | ~~CVE-2025-43429~~ (bug 298232) | ~~`StringPrototype` → ICU int32 length overflow~~ | 7a45348e0e20 (Nov 2025) | **FIX BACKPORTED** — `StringPrototype.cpp:1937` `if (view.length() >= (1 << 30)) throwOutOfMemory` with the `rdar://160634825` fix comment, directly above the previously-cited 1952–1963 call. Case-convert path (`:1646-1652`) unguarded but infeasible: needs >1G chars (>2 GiB) vs the applet's ~341 MiB WKC heap. | **NONE — guarded/infeasible** | demoted; `strnorm.html` parked |
| 2 | **CVE-2026-20608** (bug 303357) | `Object.seal/freeze` applies attributes to **private fields** → structure corruption | 672cdd38781c (Mar 2026) | likely (`JSObject.cpp:2608-2621`, no private-field exclusion) | FULL — `Object.freeze(this)` in constructors/private methods; **caller-chain check still owed** (see §4 lesson) | crash-class; structure transitions can escalate |
| 5 | **CVE-2025-24213** (bug 286694) | WebAudio ARM-only type confusion (`DenormalDisabler` never worked on ARM) | 4c65775f049b (Feb 2025) | **baseline-verified** — `platform/audio/DenormalDisabler.h:44,107` (MSVC/SSE only) | GATED on `AudioContext` hardware presence (capsweep answers) | arch-specific — x86 testers structurally miss it |
| 6 | CVE-2026-43716 (bug 313473) | "memory handling" crash, WSA-2026-0004 sibling of 43715 | ~Jun 2026 | unresolved (restricted) | unknown | font-adjacent lead |
| 7 | CVE-2026-64757 (bug 315082) | memory corruption, **same researchers as 43715** (Nasr/Carlini) | ~Jul 2026 | unresolved | unknown | likely same/adjacent subsystem |
| 8 | CVE-2024-44244 (bug 279780) | memory corruption (Q1IQ/P1umer) | ~Oct 2024 | unresolved | if JSC-runtime: live | reporters' history favors JSC |
| 9 | CVE-2026-43676 (bug 317231) | OOB access | ~Jun 2026 | unresolved | unknown | post-horizon; OOB class preferred |
| 10 | CVE-2023-42970 + CVE-2023-42875 | Accessibility UAF/raw pointers; `ENABLE_ACCESSIBILITY 1` locally | Sep 2023 | partial (`AXObjectCache.cpp:1192-1195` still passes `.get()`) | GATED on WKC AX wiring in-applet | RCE-class if AX cache instantiates |
| 11 | CVE-2023-37450 / CVE-2026-28883 / CVE-2026-43699 / CVE-2025-13502 / CVE-2025-66287 | unknown / UAF / UAF / overflow / crash | 2023–2026 | unresolved | unknown | open leads, low confidence |

**Verified exclusions (dead on this build):** all DFG/FTL/B3/IC/Air bugs
(23222, 44308, 42917, 27808/27833/27851, 54505/54508, 31206, 43438,
43529, 32439 — see `WEBKIT-NDAYS.md` §1.6 correction), all WASM (32435,
43010, 31204, 43431/2/4, 20644, 28857), WebKit2/IPC-only (41983, 42890 —
no NetworkProcess in tree), CoreText (41990), features absent at fork
(31223 FastStringifier, 42852 /v-strings, 43705 TransformStream-C++),
post-fork regressions (32373, 42950), info-only (30425).

## 2. Surface map (unpatched-bug density)

1. **JSC interpreter + runtime object model (densest)** — frozen: GC rooting
   (ArgList/MarkedVector), string/Unicode/ICU, Structure/private-fields,
   Yarr interpreter, typed arrays, Intl. All plain-JS reachable, nothing
   JIT-gated.
2. **Font pipeline** (`CSSFontFace*`, `FontFaceSet`, `CachedFont`,
   `DocumentFontLoader`) — proven 2x; siblings 43716/64757 unresolved.
3. **Post-late-2025 WebCore** — only fixes AFTER the roll-forward horizon
   count (WSA-2026-0003/4/5 UAF/OOB set).
4. **Compile-time-on, hardware-uncertain:** WebAudio (24213 waits on
   capsweep's AudioContext check), Accessibility.

## 3. Kit integration

- `varargs.html` (43000 oracle) and `strnorm.html` (43429 oracle) — being
  added to the strike kit, same phase-gate conventions as `fontchain.html`.
- capsweep's AudioContext + gamepad probes resolve candidate #5's gate.
- The 43000 victim-shaping phase (if the oracle fires) targets typed-array
  backing stores in the marshalled-args buffer → the **JSC-object-level
  primitive** the CSSFontFace chain never reached (its 16 MB window is
  engine-external; 43000 corrupts inside the JSC heap directly).

## Sources

WebKitGTK WSA-2023-0001…WSA-2026-0005 · WebKit git fix commits (per row) ·
bugs.webkit.org IDs (per row) · LinearFox CSSFontFace writeup · ntfargo
PoC gist · Red Hat CVE-2025-24213 · Kaspersky Triangulation · local tree
verification at `vendor/nintendo-oss/` (file:line per row).

## 4. The reachability lesson (2026-11-11 correction wave)

Two top-ranked candidates (CVE-2023-43000, CVE-2025-43429) were demoted
after a second-pass reachability review (raised by a parallel reviewer):

- **43000**: "the vulnerable line is present" proved nothing — its only
  dispatch path is the DFG-checkpoint OSR-exit resume, compiled out.
  Rule: for every candidate, trace the FULL caller chain on THIS build's
  config (who calls it, who creates the required state, is any of that
  compiled in) — presence of the buggy code is necessary, never sufficient.
- **43429**: the fix was backported (rdar://160634825 guard) despite the
  JSC subsystem being "frozen" — the roll-forward horizon is per-FILE, not
  per-subsystem. Rule: check for the specific fix hunk, not the subsystem
  average.

Live candidates after this wave: **CVE-2026-43715** (proven, fontchain),
**CVE-2026-20608** (owed a caller-chain check), **CVE-2025-24213** (gated on
AudioContext hardware probe), unresolved post-horizon WebCore set
(43716/64757/43676/44244…).
