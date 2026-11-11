# JSC JIT verdict + WebKit n-day triage — fw 23.0.1 dump (wkc3)

> **2026-11-11: the n-day candidate table in §2 is superseded by
> `docs/NDAYS-V2.md`** (corpus diff against the OSS source tree; §2 was
> built without source access and on the wrong JIT-ON model). §1's decode
> *data* remains valid as binary ground truth; its §1.6 interpretation is
> superseded (see the banner there).

Date: 2026-11-10. Extends `docs/WEBKIT-ANALYSIS.md` §2/§3 (W1) and answers
open questions Q6/Q8 of `docs/WEBKIT-EXPLOIT-RESEARCH.md` (W3). All dump
work is read-only against `<FW_DUMP_ROOT>`
(untrusted, never executed); disassembly with rizin 0.9.1; upstream source
comparisons against the `webkitgtk-2.39.1` tag (the fork-point window W1
fingerprinted). Companion tool: `tools/jsc_options.py` (stdlib-only,
`--self-test`, reproduces every §1 number).

Offset conventions as in WEBKIT-ANALYSIS.md: `text+X` / `mod+X` = offset in
the decompressed wkc3/wkc2 module image.

---

## 1. Task A — JSC runtime JIT verdict (offline, from the dump)

### 1.1 The option table and where defaults live

JSC's option metadata table `Options::s_constMetaData[]` (402 options,
0x18-byte rows `{name*, desc*, Type u8, Availability u8, offOption u16,
offDefault u16}` per upstream `runtime/Options.cpp` at 2.39.1) is at
**wkc3 mod+0x253dcc0..0x2540270**, name pointers relocated into `.ro`. The
runtime values live in `g_jscConfig.options` (object at **mod+0x25ca000**
in `.bss`, reached through a pointer slot at **mod+0x25814e8**; member
offset 0x40).

At this vintage defaults are **not** a rodata blob: upstream
`Options::initialize()` instantiates `INIT_OPTION` per option (a value slot
plus a `name##Default` twin), which clang compiles into **packed constant
stores** — e.g. `stp xzr, x24, [x19, 0x58]` with `x24 = 0x0101010101010101`
sets `useLLInt`/`useJIT`/`useBaselineJIT`/`useDFGJIT` (value+default each)
to true in one instruction. The `std::call_once` lambda body is at
**text+0x776010** (found as: loads the config slot early, then ~233
constant stores into the options span; its cold tail carries the 439-strong
`JSC_<option>` env-override block at text+0x776968..0x7790cc).
`tools/jsc_options.py` locates table → slot → lambda and decodes every
store symbolically (movz/movn/movk, ORR bitmask-immediates, strb/h/w/x,
stur, stp; register aliasing), cross-validated against rizin ground truth.

### 1.2 Compiled-in defaults (the verdict table)

| option | value | default (INIT) | upstream 2.39.1 expectation |
|---|---|---|---|
| useLLInt | 1 | **1** | true |
| **useJIT** | 1 | **1** | `jitEnabledByDefault()` = true (arm64 constexpr) |
| **useBaselineJIT** | 1 | **1** | true |
| **useDFGJIT** | 1 | **1** | true |
| **useFTLJIT** | 1 | **1** | true |
| useRegExpJIT | 1 | **1** | true |
| useDOMJIT | 1 | **1** | `is64Bit()` = true |
| useConcurrentJIT | 1 | **1** | true |
| useWebAssembly / useWasmLLInt / useBBQJIT / useOMGJIT | 1 | **1** | true |
| useWebAssemblyFastMemory | 1 | 1 (→0 post-init) | true, `overrideDefaults` disables w/o signaling memory |
| **useJITCage** | 0 | **0** | `canUseJITCage()` = **false** outside Apple JIT_CAGE builds |
| thresholdForJITAfterWarmUp / -Soon | 500 / 100 | 500 / 100 | matches |
| thresholdForOptimizeAfterWarmUp / -Soon | 1000 / 1000 | 1000 / 1000 | matches |
| thresholdForFTLOptimizeSoon / -AfterWarmUp | 1000 / 100000 | 1000 / 100000 | matches |
| jitPolicyScale | 1.0 | 1.0 | matches |

Options written only in the lambda's cold tail (decode shows `?`; values
read manually from the rizin cross-check): useJITCage **0**, useShadowRealm
**0**, useTemporal **0**, useSharedArrayBuffer **0**, useDollarVM **0** —
i.e. the experimental feature surfaces W1 found *implemented* in strings
are **compiled with default-off flags** (of these, ShadowRealm/Temporal are
JS-visible feature gates; they are OFF unless something flips them).

Every decoded JIT-tier default matches the upstream 2.39.1 expectation for
an arm64 GTK-lineage build. **No JIT-disable divergence exists in the
compiled-in defaults.**

### 1.3 Override surfaces

- **Env override is compiled in**: wkc3 `.ro` contains **439 `JSC_<option>`
  literals** (e.g. `JSC_useJIT` at ro+0x1eb7505) and wkc3 **imports
  `getenv`** — the upstream non-Cocoa `overrideOptionWithHeuristic` path.
  At runtime, `JSC_useJIT=0` in the process environment *would* be honored.
  Nothing page-reachable sets applet environment, so this is not an attack
  surface, but it is the cleanest **on-rig enable/disable knob** for
  experiments (if the applet env can be influenced by the loader at all).
- **Applet-level override: none found.** `--applets` scan of 0x1042 / 0x1043
  / 0x100f / 0x104b `main` for `JSC_`/`useJIT`/`jitEnabled`/disable-JIT
  strings: **0 hits in all four**.
- **WKC settings surface**: wkc3 exports only `WKCSettings::setJavaEnabled`,
  `setJavaScriptCanOpenWindowsAutomatically`, `WKCWebFrame::setJavaScriptPaused`
  etc. — on/off switches, no JIT tier toggle in the C API.

### 1.4 Executable-memory plumbing (evidence chain)

W1's §3.5 claim "wkcMemorySetExecutablePeer (W^X toggle)" needs a
correction — in the shared-Dll build these peers are **stubs**:

| peer (wkc2 `peer_wkc`) | address | what it actually does |
|---|---|---|
| `wkcMemorySetExecutablePeer` | text+0xa2d0 | **`ret`** — no-op stub |
| `wkcMemoryCacheFlushPeer` | text+0xa2d4 | **`ret`** — no-op stub |
| `wkcMemoryExecutableMallocPeer` | text+0xbc44 | loads registered proc from [0x12f578]; if NULL calls the default (import); then a bookkeeping call with flag=1 |
| `wkcMemorySetAllocateMemoryPagesProcPeer` | text+0xb444 | stores the engine-registered page-allocator proc to [0x12f568] (twin Free setter at 0xb454 → [0x12f570]) |

No module imports the exec peers via dynsym — the engine binds them by
registration (`wkc3` imports `wkcMemorySetAllocateMemoryPagesProcPeer` /
`...FreeMemoryPagesProcPeer`, not the malloc/exec peers). The default path
resolves to imports **`nn::os::AllocateMemoryPages` / `nn::os::FreeMemoryPages`**
(wkc2 → applet `main` exports at 1043-main text+0x1884f0 / +0x25a70).

`nn::os::AllocateMemoryPages(addr, size)` → applet code at 0x189ce0 →
bookkeeping walk of the region tree (global at [0xc7c368]) →
**`bl svc-0x2C-thunk` at 0x189dbc** — with the project's Switch-2 svc
table (`tools/npdm.py`): 0x2C = **MapPhysicalMemory**, 0x2D =
UnmapPhysicalMemory. The svc thunks are one-instruction `svc N; ret`
entries in a 50-entry block at 1043-main text+0x1a3d00-0x1a3e34 which
includes the NPDM-allowed **0x48/0x49 (Uns(afe) map)** and **0x80**
(Switch-2-only). Callers found: svc 0x48/0x49 used only by nnSDK "unsafe
memory" wrappers at 0x18f620-0x18f754; **svc 0x80 has six call sites**
(0x484c80…0x48d288) in one subsystem, called as `(x0, x1, 0x20, 0x20)`
(addr, size, perm?, perm?) behind a registered callback with
`pacia`-signed dispatch — exact semantics UNKNOWN (no public Switch-2 svc
table); plausibly a permission/dual-map primitive, unlabeled speculation.
svc 0x02 (SetMemoryPermission) exists with 4 call sites (e.g. 0x18bdb0
with perm=0 — decommit).

Note: the applet's svc set has **no FlushDataCache (0x2B)** and the
cache-flush peer is a stub — consistent with either uncached JIT pages or
coherence-by-(un)map; one runtime probe resolves this (§1.6).

### 1.5 The hypothetical attacker call (post-ARW, call-oriented)

Because `br`/`blr` are unauthenticated (no BTI; WEBKIT-ANALYSIS §3.1-2) and
JITCage is compiled out, an ARW primitive in the applet process can call
any in-process address directly:

1. `wkc2!wkcMemoryExecutableMallocPeer(size)` (wkc2 text+0xbc44) — returns
   a pointer from the executable pool that `WKC::Heap::
   GetJSJITCodePageAllocatedBytes` (wkc3 export) accounts for. Backed, via
   the registered proc or default, by `nn::os::AllocateMemoryPages` →
   svc 0x2C.
2. Write the stub through the ARW — the pool must be engine-writable for
   JIT codegen; with `SetExecutable` a no-op, the working hypothesis is
   the pool is **RWX** (or dual-mapped RW/RX via svc 0x80's 0x20/0x20
   args) — this is the one genuinely static-unknowable point.
3. No flush needed (`CacheFlushPeer` = `ret`); if coherence is required,
   unmap/remap (svc 0x2D/0x2C) is the pattern the applet itself has.
4. Transfer control: overwrite a JSC function entry / native-callback
   pointer, or `blr` the stub from a call-oriented pivot.

Reachability summary: the peer API is **not** part of the C surface the
applet binds (applet imports = 319 `WKC::` + **41** JSC C-API functions —
`JSContextGetGlobalContext`, `JSObjectMakeFunctionWithCallback`,
`JSObjectGetTypedArrayBytesPtr`, `JSValueToNumber`, … full list in §6;
W1's "42" count re-measured as 41). It is engine-internal plumbing. That
distinction is irrelevant post-ARW (any address is callable) but rules out
reaching it without memory corruption first. The JSC C API *exports* of
wkc3 (110 functions) remain the nicest post-ARW surface for minting
contexts/objects.

### 1.6 JIT verdict (one paragraph)

> **2026-11-11 SUPERSEDED — the verdict below is WRONG. See
> `docs/WEBKIT-ANALYSIS.md` §3.5 (corrected).** The Nintendo GPL archive
> (`vendor/nintendo-oss/`) proves `ENABLE_JIT 0 / DFG 0 / FTL 0 /
> C_LOOP 1`. The decoded "true" values above are dead letters
> (`OptionsList.h` rows are unconditional; `jitEnabledByDefault()` is
> `is32Bit() || isAddress64Bit()` = true in any build), and
> `runtime/Options.cpp:438-440` additionally calls `disableAllJITOptions()`
> under `!ENABLE(JIT)` — a runtime belt-and-braces on top of the
> compile-time strip. There are no JIT pages, no tiering, no FTL GCSE.
> Every JIT-dependent conclusion below (incl. the 32439 port plan §3.1)
> is withdrawn.

**[SUPERSEDED — historical record]** **JIT is ON.** The fork-point
(WebKitGTK 2.39.1-window) `Options::initialize`
lambda compiled into wkc3 sets **useJIT, useBaselineJIT, useDFGJIT,
useFTLJIT, useRegExpJIT, useDOMJIT (and every WebAssembly tier) to true —
value and default both —** with stock tiering thresholds (500/100/1000/
1000/1000/100000, jitPolicyScale 1.0) and **useJITCage = false** (no JIT
cage, as expected for a non-Apple build). No disable-override exists
anywhere in the four applet binaries, and the only override channel is the
upstream env-var path (`JSC_*` literals + `getenv`), which nothing
page-reachable controls. Executable memory is really plumbed: engine →
registered allocator procs / `wkcMemoryExecutableMallocPeer` →
`nn::os::AllocateMemoryPages` → svc 0x2C MapPhysicalMemory, with NPDM
permission for 0x48/0x49/0x80 present; but the W^X toggle and cache-flush
peers are `ret`-stubs in this build, so the pool is presumably RWX (or
remap-coherent) — the single remaining runtime check. **This upgrades
strategy #2 in WEBKIT-EXPLOIT-RESEARCH §6 from "if runtime JIT on" to
"JIT on; only pool permissions unverified"**, and it invalidates the
Switch-1-precedent assumption ("browser has no JIT") for Switch 2: a JSC
memory-corruption primitive that survives to FTL tiering yields JIT-page
native execution with no PAC forgery and no cage.

---

## 2. Task B — n-day triage for the 2.39.1-vintage engine

Method: for each candidate — component (JSC/WebCore/ANGLE), bug class,
ITW/PoC availability (public writeups, exploit-db, GitHub), ARW yield in a
**single-process JSC** context (the Switch-2 applet has no renderer
sandbox; WEBKIT-ANALYSIS §5), then a **local presence check** against
wkc3/upstream-2.39.1 source shape. `CONFIRMED-PRESENT` below means the
vulnerable code shape is in the `webkitgtk-2.39.1` tree (the fingerprinted
fork point) AND the relevant machinery is visible in the wkc3 binary — the
caveat is always that Nintendo's fork could have backported a fix (only a
per-bug binary diff of the exact code closes that; see §4.3).

### 2.1 Candidates table (ranked)

| # | CVE / bug | component | class | ITW | public PoC/RCA | ARW yield (single-proc JSC) | presence in wkc3 | port effort |
|---|---|---|---|---|---|---|---|---|
| 1 | **CVE-2023-32439** | JSC DFG (`DFGClobberize.h`) | type confusion (bool↔number via FTL GCSE) | yes (Triangulation wave; CISA KEV) | **full RCA ×2 + trigger PoC** (pksecurity, shxdow) | ~~high~~ **DEAD (2026-11-11 re-triage)** — DFG CSE heap-location collision (fix commit `52fe95e5805c`, bugs.webkit.org #256567); DFG is compile-time-stripped (`ENABLE_DFG_JIT 0`) AND runtime force-off (`Options.cpp:438 disableAllJITOptions()`); no C_LOOP counterpart exists — the pre-fix code in our tree (`DFGClobberize.h:356-407`, confirmed) is unreachable dead code | CONFIRMED-PRESENT (source, but unreachable) | **n/a — DEAD** |
| 2 | **"clobber-the-world" prototype bug** (Enki writeup; iOS 16.5.1-era RSR batch; writeup authors say *not* CVE-2023-37450 — CVE unassigned in their analysis) | JSC runtime+DFG AI (`JSObject.cpp`) | side-effect/clobberize confusion → configurable `prototype` OOL property | not stated | **trigger + type-confusion PoC** (Enki/Medium) | high — writeup says ARW "not a hard task" from the confusion | **CONFIRMED-PRESENT** (2.39.1 `definePropertyOnReceiver` has no `canDefinePropertyOnReceiverFast` guard; `op_put_by_id_with_this` machinery strings in wkc3) | **medium** |
| 3 | CVE-2023-41074 | JSC (DFG-required) | integer overflow | yes (Safari 17, pre-16.7 ITW) | none public (no RCA, no PoC) | likely high (class) — **DEAD if DFG-tier (per §1.6 correction, no JIT)** | UNKNOWN (bug existed pre-16.7; exact function unpublished) | high (blind) |
| 4 | CVE-2023-23529 | WebKit | type confusion | yes (first 2023 WebKit 0-day) | none public | unknown | UNKNOWN | high |
| 5 | CVE-2023-32435 | WebKit | memory corruption ("improved state management") | yes (Triangulation) | none public (Kaspersky withheld WebKit internals) | unknown | UNKNOWN | high |
| 6 | CVE-2023-41983 | WebKit/JSC | memory handling (UAF-class) | yes (Safari 17.1) | none public | unknown | UNKNOWN | high |
| 7 | CVE-2023-42917 | WebKit DFG | race / missing write barrier ("flattenDictionaryStructure race" per PS5 research) | yes (Safari 17.1.2) | none public (PS5 repo failed to repro) | ~~useConcurrentJIT=1 so races apply~~ **DEAD — DFG-tier + concurrent JIT nonexistent (§1.6 correction; disableAllJITOptions sets useConcurrentJIT path moot)** | UNKNOWN | n/a |
| 8 | CVE-2024-44308 | JSC DFG | uninit stack slot (spill emitted after slow-path jump) | yes (Nov 2024; CISA KEV) | **full public exploit** (Exodus 2025-08) | high (butterfly overwrite → addrof+ARW) | **ABSENT** — 2×-checked: (a) 2.39.1 `compilePutByValForIntTypedArray` allocates its single scratch *before* the slow-path jump (the buggy `scratch2`-after-jump shape is a later regression, RAB-era), (b) **RAB itself is absent** (no resizable/growable-ArrayBuffer strings in wkc3) | n/a (not portable back) |
| 9 | CVE-2025-31200 | **CoreAudio** (NOT WebKit — corrects WEBKIT-ANALYSIS §2.3) | OOB in media decode | yes | none public | n/a (component absent) | **ABSENT** (Apple framework) | n/a |
| 10 | CVE-2025-31201 | WebKit | UAF-class (fixed by *removing* code) | yes | none public | unknown (introduction date unknown → may postdate fork) | UNKNOWN | high |
| 11 | CVE-2025-43529 / CVE-2025-43541 | WebKit | UAF (ITW, Safari 26.2) / type confusion (crash-level, ZDI) | 43529 yes / 43541 no | none public | 43529 unknown; 43541 crash-level | UNKNOWN | high / low value |
| 12 | CVE-2025-14174 | **ANGLE** | OOB (Metal path) | yes | public analysis + PoC (GitHub) | n/a for us | **ABSENT** — no ANGLE in wkc3 (only `SVG_ANGLE*` constants; graphics = Cairo/GL, WebGL2 present) | n/a |
| 13 | Exodus "Shifting Boundaries" (B3 `IntRange::shl`) | JSC FTL/B3 | integer-range miscompile → OOB | n/a (2020 research) | full PoC | high | **ABSENT — pre-window**: patched May 2021, before the 2.39.1 fork point (kept here as the canonical FTL-range exploit methodology reference) | n/a |

Excluded as not-engine: CVE-2023-38606/32434 (kernel), CVE-2023-41990
(ADJUST font), CVE-2024-44309 (WebKit cookies/WebCore, identity-theft
class, no memory corruption).

### 2.2 Presence cross-check details (the local evidence)

**CVE-2023-32439 — CONFIRMED-PRESENT.** Upstream `dfg/DFGClobberize.h` at
`webkitgtk-2.39.1` lines 366-401 contains the exact vulnerable shape later
fixed (WebKit commit `52fe95e`, June 2023): one `case
EnumeratorNextUpdateIndexAndMode: case HasIndexedProperty:` block where
**both ops `def(HeapLocation(HasIndexedPropertyLoc, ...))`**, letting FTL
GCSE replace `HasIndexedProperty` (SpecBoolean) with
`EnumeratorNextUpdateIndexAndMode` (SpecBytecodeNumber) — the
boolean-number confusion. The trigger machinery is compiled into wkc3:
`JSPropertyNameEnumerator` GC subspace ("Isolated JSPropertyNameEnumerator
Space"), `computeNext`, `opEnumeratorGetByVal` slow-path strings, and FTL
GCSE (options `useFTLJIT=1`, tiering thresholds stock). Trigger conditions
per the RCAs: FTL tier + `for…in` (IndexedMode) and `in` on the same
Int32/Double/Contiguous array, index 0.

**"clobber-the-world" prototype bug — CONFIRMED-PRESENT.** At 2.39.1,
`runtime/JSObject.cpp::definePropertyOnReceiver` (lines 891-918) falls
through to `putInlineFast` with **no** `canDefinePropertyOnReceiverFast()`
guard (the guard is the mid-2023 fix) — so `super.prototype = 1` on a
class extending Function converts the non-configurable `prototype` into a
configurable OOL property without firing structure-transition watchpoints;
a getter attached that way is invisible to DFG clobberization → type
confusion (writeup demonstrates via the Spread opcode). wkc3 contains the
`op_put_by_id_with_this` handler strings (rodata) — the trigger bytecode
path is compiled in.

**CVE-2024-44308 — ABSENT (double evidence).** (1) In 2.39.1's
`DFGSpeculativeJIT.cpp`, `compilePutByValForIntTypedArray` allocates its
single `GPRTemporary scratch` *before* `getIntTypedArrayStoreOperand`
emits the `branchTruncateDoubleToInt32` slow-path jump — the vulnerable
shape (a second scratch allocated *after* the jump, its spill skipped on
the slow path) is a later refactor, consistent with Exodus analyzing
Safari 17.6. (2) The published trigger stores a double into a
**resizable** ArrayBuffer-backed typed array; wkc3 has **no RAB support**
(no `resizable`/`growable` ArrayBuffer strings; `useResizableArrayBuffer`
option absent per W1 §2.2). Both independently rule the bug out of this
engine.

**CVE-2025-14174 — ABSENT**: no ANGLE in wkc3 (grep: only SVG angle
constants; the engine's graphics stack is Cairo/GL per WEBKIT-ANALYSIS
§1.1). **CVE-2025-31200 — ABSENT**: CoreAudio is an Apple framework; the
WebKit sibling of that release is CVE-2025-31201 (kept UNKNOWN).

### 2.3 Ranking rationale

Score = ARW-yield × PoC-availability × presence-confirmed. The top two are
the only candidates with all three factors non-zero:

1. **CVE-2023-32439** — JSC-side, full public root cause + trigger PoC,
   FTL confirmed ON by §1, presence confirmed at the fork-point source
   shape, exploitation path (addrof/fakeobj → butterfly ARW) is standard
   JSC and needs no PAC/JIT-cage work (useJITCage=0, §1.2).
2. **"clobber-the-world" prototype bug** — runtime+DFG-AI side, public
   trigger and confusion PoC (no full chain), presence confirmed at the
   source level; exploitation requires a DFG-AI-cooperating victim shape
   (the writeup's Spread trick), slightly more porting art than #1.

Everything else loses on PoC availability (3-7, 10-11: no public root
cause → blind fuzzing on a fork whose divergence is unknown), on presence
(8, 9, 12, 13 absent), or on value (11/43541 crash-level).

---

## 3. Porting plan for the top two

### 3.1 CVE-2023-32439 → wkc3 (primary)

1. **Rebuild the trigger against 2.39.1 semantics** (the public PoCs
   target ~16.4/16.5 trees): loop body with `for (let k in arr)` where the
   enumerator runs IndexedMode over an Int32 (then Double) array; the same
   array tested with `k in arr` at index 0; both inside one hot function
   driven past FTL entry (thresholds: ~1000/100000 warm-up counters —
   stock, §1.2). The confusion makes `in` return the numeric enumerator
   index where a boolean is speculated → mis-typed value flowing into a
   branch/select.
2. **Rig verification first (captive-portal telemetry page)**: host the
   probe on the portal rig; telemetry reports (a) whether the `in` result
   ever looks non-boolean (JS-observable oddity = miscompile reproduced),
   (b) tier-up confirmed (timing signature of FTL compilation, e.g. ~10⁵
   invocation latency spike — release build, no dumpOptions). One page,
   two measurements, no crash needed.
3. **Primitives**: follow the RCA recipes — confuse `ArrayWithInt32` vs
   `ArrayWithDouble` storage to read a double-encoded pointer (addrof) and
   plant a fake object (fakeobj); escalate to butterfly swap for stable
   ARW (same mechanics as the public 32439 writeups and the Exodus 44308
   chain, all portable to 2.39-era JSC layouts).
4. **Native step** (per §1.5): ARW → call `wkcMemoryExecutableMallocPeer`
   → write stub → transfer control. No PAC forgery needed (no BTI, B-key
   PAC only guards returns; call-oriented path unaffected); no JIT cage.
5. **Divergence check before investing**: diff wkc3's clobberize code
   against upstream 2.39.1 — the June-2023 fix added a distinct
   `EnumeratorNextUpdateIndexAndModeLoc` LocationKind; its *absence* in
   wkc3's binary (the fix would change the DFGGCSE hash-switch shape) is
   verifiable offline with moderate RE. Until then, presence rests on the
   fork-window fingerprint (strong but not per-line).

### 3.2 "Clobber-the-world" prototype bug (secondary)

1. Trigger per the writeup: `class F extends Function {}` /
   `super.prototype = <obj>` writes; attach a getter to the now-OOL
   configurable `prototype`; DFG-AI believes a Spread over the object is
   side-effect-free while the getter mutates a victim element → type
   confusion.
2. Rig probe: a page that runs the trigger under warm-up and reports via
   telemetry whether a spread produced a stale-typed value (crash-free
   detection).
3. Same primitive ladder as 3.1.3-4. The guard function's absence at the
   fork point is source-verified; a quick binary sanity check is that
   `putInlineFast`'s prototype path exists in wkc3 (strings already
   confirm the bytecode path).

### 3.3 What NOT to spend time on

CVE-2024-44308 (bug postdates the fork; RAB absent — would need a
different bug), ANGLE/14174 and CoreAudio/31200 (components absent),
pre-2021 bugs (patched before fork), and any candidate without a public
root cause until the rig can fuzz (blind n-day hunting on a diverged fork
is the worst effort/reward ratio; better: differential fuzz the two
CONFIRMED-PRESENT bug *families* — clobberize/HeapLocation collisions and
definePropertyOnReceiver-style watchpoint misses — against desktop JSC at
the same vintage, which is exactly where 32439-class bugs cluster).

---

## 4. Answers to W3's open questions + new ones

- **Q8 (JIT runtime enablement)**: answered — §1.6, JIT ON by compiled-in
  default, no override anywhere in the stack.
- **Q6 (n-day supply)**: materially improved — two CONFIRMED-PRESENT
  candidates with public writeups (32439, prototype-bug), both JSC-side
  and both compatible with the single-process ARW→fs-chain strategy.
- New open questions (ours to track):
  1. **Pool permissions** at the far end of
     `wkcMemoryExecutableMallocPeer` (RWX vs RW/RX dual-map via svc 0x80)
     — one rig probe (§3.1.2 extension: after ARW, read pool PTE bits via
     QUERY_MEMORY-style side channel or observe JIT-write behavior).
  2. **svc 0x80 semantics** (the 0x20/0x20 args subsystem) — needs
     kernel-side RE or a Switch-2 svc table leak; currently UNKNOWN.
  3. **Fork divergence per candidate** — the June-2023 clobberize fix and
     the 16.5.1-RSR `canDefinePropertyOnReceiverFast` fix could have been
     backported by Nintendo; §3.1.5/§3.2.3 give the checks.

---

## 5. Reproduction

```sh
python3 -I tools/jsc_options.py --self-test
python3 -I tools/jsc_options.py '<dump>/040000000000085d/wkc3'
python3 -I tools/jsc_options.py --applets '<dump dir>'
# spot disassembly:
rizin -q -c 'e asm.arch=arm; e asm.bits=64; pd 3 @ 0x08000000+0xa2d0' \
  '<dump>/040000000000085d/wkc2'        # the two ret-stubs
rizin -q -c 'e asm.arch=arm; e asm.bits=64; s 0x1884f0; pd 6' \
  <decompressed 1043 main text>         # AllocateMemoryPages export
# upstream comparisons: raw.githubusercontent.com/WebKit/WebKit/webkitgtk-2.39.1/
#   Source/JavaScriptCore/dfg/DFGClobberize.h        (lines 366-401)
#   Source/JavaScriptCore/dfg/DFGSpeculativeJIT.cpp  (lines 3775-3895, 3922-3990)
#   Source/JavaScriptCore/runtime/JSObject.cpp       (lines 891-918)
```

## 6. The 41 JSC C-API imports (0x1043 main; 0x1042/0x104b identical set)

JSContextGetGlobalContext, JSContextGetGlobalObject,
JSObjectCallAsConstructor, JSObjectCallAsFunction,
JSObjectGetArrayBufferByteLength, JSObjectGetArrayBufferBytesPtr,
JSObjectGetProperty, JSObjectGetPropertyAtIndex,
JSObjectGetTypedArrayBuffer, JSObjectGetTypedArrayBytesPtr,
JSObjectHasProperty, JSObjectMake, JSObjectMakeArray, JSObjectMakeDate,
JSObjectMakeError, JSObjectMakeFunctionWithCallback,
JSObjectMakeTypedArray, JSObjectSetProperty,
JSStringCreateWithUTF8CString, JSStringGetCharactersPtr, JSStringGetLength,
JSStringRelease, JSValueGetTypedArrayType, JSValueIsBoolean,
JSValueIsInstanceOfConstructor, JSValueIsNull, JSValueIsNumber,
JSValueIsObject, JSValueIsString, JSValueIsUndefined, JSValueMakeBoolean,
JSValueMakeNull, JSValueMakeNumber, JSValueMakeString, JSValueMakeUndefined,
JSValueProtect, JSValueToBoolean, JSValueToNumber, JSValueToObject,
JSValueToStringCopy, JSValueUnprotect.
(W1's doc said 42; the enumerated set has 41 entries — noted, not
material.)

## 7. Sources

- Apple advisories: [Safari 16.3.1/23529](https://support.apple.com/en-hk/102800),
  [iOS 16.5.1/32439](https://support.apple.com/en-us/106353),
  [Safari 17/41074](https://support.apple.com/en-us/120330),
  [Safari 17.1/41983](https://support.apple.com/en-ke/109049),
  [iOS 18.4.1/31200+31201](https://support.apple.com/en-us/122282),
  [Safari 26.2/43529+43541](https://support.apple.com/en-us/125892)
- NVD: [32435](https://nvd.nist.gov/vuln/detail/cve-2023-32435),
  [32439](https://nvd.nist.gov/vuln/detail/cve-2023-32439),
  [23529](https://nvd.nist.gov/vuln/detail/cve-2023-23529),
  [41074](https://nvd.nist.gov/vuln/detail/cve-2023-41074),
  [44308](https://nvd.nist.gov/vuln/detail/cve-2024-44308),
  [42917](https://nvd.nist.gov/vuln/detail/cve-2023-42917),
  [31200](https://nvd.nist.gov/vuln/detail/cve-2025-31200)
- RCAs & exploit writeups: pksecurity
  [CVE-2023-32439 RCA](https://blog.pksecurity.io/2023/07/07/cve-2023-32439-webkit.html);
  shxdow [32439 analysis](https://shxdow.me/cve-2023-32439); Exodus Intel
  [CVE-2024-44308 "Oops Safari, I think you spilled something"](https://blog.exodusintel.com/2025/08/04/oops-safari-i-think-you-spilled-something)
  (2025-08-04) and [Shifting Boundaries](https://blog.exodusintel.com/2023/07/20/shifting-boundaries-exploiting-an-integer-overflow-in-apple-safari)
  (2023-07-20); Enki
  [iOS 16.5.1 Safari RCE analysis](https://medium.com/@enki-techblog/ios-16-5-1-safari-rce-analysis-cve-2023-37450-89bb8583bebc)
  (prototype-property confusion; the authors retract the 37450 CVE
  attribution in-text); GitHub
  [CVE-2025-14174 ANGLE analysis](https://github.com/typeconfused/CVE-2025-14174-analysis);
  PS4 wiki [WebKit bugs](https://psdevwiki.com/ps4/WebKit_Bugs) (JIT-required
  classification, 42917 race note); PS5 research
  [ZigZagBoi1/PS5-14.10-Research](https://github.com/ZigZagBoi1/PS5-14.10-Research)
  (42917 repro attempts)
- Kaspersky Securelist, [Operation Triangulation series](https://securelist.com/operation-triangulation-the-last-hardware-mystery/111669)
- CISA KEV additions for 23529 (2023), 32439 (2023-06), 44308 (2024-11),
  31200/31201 (2025-04)
- Upstream WebKit @ `webkitgtk-2.39.1` (files cited in §2.2, fetched
  2026-11-10 from raw.githubusercontent.com)
- Local: `docs/WEBKIT-ANALYSIS.md` (W1 §2/§3/§4), `docs/WEBKIT-EXPLOIT-RESEARCH.md`
  (W3), `tools/webkit_version.py`, `tools/npdm.py` (Switch-2 svc names),
  `tools/jsc_options.py` (this work; `--self-test` includes ground-truth
  instruction words from wkc3 verified against rizin 0.9.1)
