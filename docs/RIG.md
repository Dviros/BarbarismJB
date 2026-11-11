# RIG — the Switch 2 WebKit entry test rig

Date: 2026-11-10. Implementation: `tools/webkit-rig/` (one-command
orchestrator: `tools/webkit-rig/launch.py`; runbook:
`tools/webkit-rig/README.md`). Mechanism and evidence base:
`docs/WEBKIT-ENTRY.md`; engine analysis: `docs/WEBKIT-ANALYSIS.md`.

The rig is the BarbarismJB delivery bench: a LAN DNS layer plus an HTTP
server that turns the console's plain-HTTP connectivity check into a
captive-portal trigger and serves our JavaScript inside WifiWebAuthApplet.
Tested target: our own Switch 2, stock firmware 23.0.1.

## What the rig proves

If a telemetry line with UA `WifiWebAuthApplet … AppleWebKit/…` appears in
`tools/webkit-rig/runs/rig-*.jsonl`, then on stock fw 23.0.1:

1. the conntest host set is live and DNS-hijackable on the LAN,
2. omitting `X-Organization: Nintendo` triggers captive-portal detection,
3. WifiWebAuthApplet opens and **follows a 302 to an arbitrary LAN
   `http://` URL** (no whitelist, no TLS),
4. attacker-controlled JavaScript executes in the applet and can call back
   out (`/report` POSTs land on the bench).

That is the complete entry surface — the delivery half of the WebKit chain.

## What the rig does NOT prove

- **No code execution.** Nothing here corrupts memory. The JSC tiering
  probe is a *heuristic* micro-benchmark (cold/hot batch-time ratio
  suggesting LLInt/baseline vs DFG-tier compilation); it does not
  demonstrate, measure, or bypass any vulnerability.
- **No exploit.** The n-day chain against the 2.39.1-window engine
  (candidate CVE classes in `docs/WEBKIT-ANALYSIS.md` §2.3) is a separate
  workstream (`docs/WEBKIT-EXPLOIT-RESEARCH.md`). The rig's probes only
  fingerprint the runtime (feature matrix, syntax support, JIT behavior)
  to inform that work. The `pages/fontchain.html` harness reproduces the
  publicly documented CSSFontFace trigger SHAPE behind a rig-side phase
  gate (phase 1 is trigger-only and reverts to it on every restart) —
  advancing to reclaim/read experiments is a deliberate operator action.
- **No persistence, no console modification.** The applet is used exactly
  as Nintendo built it (rendering a LAN captive portal); nothing is
  written to the console.

## Telemetry schema (schema 1)

Each line in `runs/rig-<server-start-ts>.jsonl` is a JSON envelope with
the page's report embedded:

```json
{"ts": "…ISO-8601…", "peer": "console IP", "host": "…", "ua": "…",
 "path": "/report", "data": { …the page's report, below… }}
```

The page POSTs twice per load — phase `env` immediately (so partial data
survives a later crash) and phase `full` after the heavier probes. Report
fields:

| field | content |
|---|---|
| `schema` | `1` |
| `phase` | `env` \| `full` \| `crash` |
| `seq` | monotonic POST counter for this page load |
| `startedAt` | page-load timestamp |
| `rig` | `{templated, base, pageHost}` — how the page addressed the bench |
| `page` | `{url, referrer, protocol}` |
| `env` | UA, platform, language(s), screen, devicePixelRatio, timezone, touch points, GPU renderer string (WebGL, best-effort) |
| `features` | typeof-matrix: fetch/XHR/WebSocket/Workers/WebAssembly/Proxy/Temporal/ShadowRealm/… (~34 entries; the 2.39.1-fork markers from WEBKIT-ANALYSIS §2.2 included) |
| `syntax` | parse probes via `new Function`: arrows/async-await/`?.`/`??`/BigInt/class fields/regex lookbehind/… |
| `jit` | `{timer, itersPerBatch, batches, batchMs[], coldMs, hotMs, ratio, verdict}` — documented heuristic |
| `ws` | WebSocket availability + open/close/timeout outcome against `/ws` |
| `posts` | per-phase attempt counts and last error |
| `errors` | guarded-probe failures `{stage, error}` (empty on a healthy run) |

Server-side access logs (both scripts) add the request-side view: every
GET/POST with Host, UA, status, and the `Upgrade-Insecure-Requests` flag.

### Schema 1b — the 32439 probe report (probe-32439.html) — RETIRED from the auto-chain

The `launch.py --auto-probe` chain (auto-swap to `probe-32439.html` after
the first applet telemetry) is RETIRED (2026-11-11): CVE-2023-32439 is an
FTL miscompile, this console's engine has NO JIT (docs/NDAYS-V2.md
verified exclusions), so the detector can never fire for the right
reason. The page survives for one deliberate use — its stage-A tiering
probe as an INVERTED falsifier: serve it manually
(`portal.py --probe-page probe-32439.html`, then local-only
`POST /rig/swap`); if stage A ever reports `jit_tiering_likely`, the
no-JIT engine model is wrong. Stage-B variant verdicts are dead weight on
this build and should be ignored. When manually served, it POSTs the same
envelope shape with `data.probe = "cve-2023-32439"` and two phases
(`env` before the stages, `verdict` at the end; a driver-level crash
leaves a `crash` phase with `data.stage = "CRASHED@…"`):

| field | content |
|---|---|
| `tiering` | stage-A cold/hot micro-benchmark `{verdict, ratio, coldMs, hotMs}`; `jit_tiering_likely` is a PRECONDITION for reading CLEAN (FTL GCSE is where the miscompile lives) |
| `variants[]` | stage-B divergence detector, one entry per trigger shape: `{name, cold:{runs,truth[]}, hot:{runs,mismatches,ms}, firstDivergence, verdict}` — `MATCH` or `VULNERABLE-INDICATED` (any hot output differing from cold ground truth: wrong value, boolean-as-number leaking into arithmetic, or a hot-only exception) |
| `negative_control` | stage-C Enki `definePropertyOnReceiver` shape; MUST be spec-correct on this engine (fix confirmed backported, WEBKIT-BACKPORT-CHECK §2) — `PASS` or `NEGATIVE-CONTROL-FAILED` (the latter falsifies the fork model) |
| `overall` | `VULNERABLE-INDICATED` \| `CLEAN` \| `CRASHED` \| `UNKNOWN` \| `NEGATIVE-CONTROL-FAILED` |

The five stage-B variants: `int32-hole-forin` and `double-hole-forin`
(the RCA's exact IndexedInt32/IndexedDouble shapes: for-in enumeration +
`in` check in one function, `in` consumed numerically), plus
`property-to-indexed`, `accessor-mid-enum`, and `proto-chain-change`
(the three side-effect shapes the optimizer must model around the
enumerator). The page is built from the public root-cause SHAPE, not a
copied PoC (we have none) — see its header comment and
`docs/WEBKIT-BACKPORT-CHECK.md` §5.

`UNKNOWN` means stage A could not confirm JIT tiering on that load (or a
variant errored before comparison); it is NOT clean — re-run with the
applet open longer before drawing conclusions.

### Applet strike kit (pages/ — capsweep, wsagent, fontchain, pngztxt, freeze, webp4863; pages/parked/ is dead)

`tools/webkit-rig/pages/` holds the strike kit: every top-level `*.html`
in it is auto-registered by filename stem at portal.py startup (same
`{{RIG_HOST}}/{{RIG_PORT}}` templating as the other pages). Each page is
served directly at `/page/<name>` and can be force-swapped onto `/portal`
(the URL the applet follows) with a local-only control POST:

```bash
# serve one to the applet (from the bench host only)
curl -X POST 'http://127.0.0.1:8080/rig/swap?name=fontchain'
curl -X POST 'http://127.0.0.1:8080/rig/swap?name=capsweep'   # or wsagent
# no-arg POST stays back-compat: swap to the --probe-page (32439 falsifier)
# direct test load (any LAN peer, no swap needed)
curl http://<rig-ip>:8080/page/wsagent
```

**PARKED-DEAD — `pages/parked/varargs.html` and
`pages/parked/strnorm.html`.** Both oracle pages are RETIRED FROM SERVICE
(2026-11-11 reachability re-check, docs/NDAYS-V2.md §1 + §4) and moved
under `pages/parked/`: parked pages are never auto-registered (only
top-level `pages/*.html` register), never servable at `/page/…`, and
never swappable — the self-test asserts exactly that.

- **varargs.html (CVE-2023-43000)**: DEAD CODE PATH — the vulnerable
  `MarkedVector::fill` at `LLIntSlowPaths.cpp:2318` is dispatched ONLY by
  `llint_slow_path_checkpoint_osr_exit` → `popCheckpointOSRSideState`,
  whose sole creator is `dfg/DFGOSRExit.cpp:239`; DFG is compiled out on
  this no-JIT build, so nothing ever pushes the side state and the buggy
  fill can never run for the right reason (plain `f(...x)` uses the
  stack-based `varargsSetup`).
- **strnorm.html (CVE-2025-43429)**: GUARDED — the rdar://160634825 fix
  WAS backported: `StringPrototype.cpp:1935-1939` throws OOM for
  `length >= (1 << 30)` directly above the normalize call site; the
  case-convert path is unguarded but infeasible (>2 GiB strings vs the
  ~341 MiB applet heap).

The full design/write-ups stay in the parked files' headers for
archaeology; the pages parse (node --check) if ever revived.

**capsweep.html — one-shot capability census.** Auto-runs on load: typeof
matrix over the confirmed/dead API lists + fork markers, syntax probes,
UA/viewport/language/timezone/gamepad, localStorage quota grow-test,
WebSocket connect-back (`/ws?role=probe`: open -> welcome -> close timings),
Worker spawn + message roundtrip (captures the worker-side UA), Canvas 2D
draw->getImageData->putImageData roundtrip with FNV-1a pixel hash,
FontFace remote load (intentionally missing `/stage/capsweep-remotefont.woff2`
— the 404 in the access log IS the remote-fetch evidence) plus a
`local()` load, performance.now resolution (adaptive delta sampling),
structuredClone/Proxy/FinalizationRegistry presence, window.onerror +
unhandledrejection capture, and a 20-kernel C_LOOP timing fingerprint
(raw 3-sample timings per kernel; interpretation is bench-side).
Telemetry: phase `env` immediately, one phase `full` JSON POST at the end
(retried with backoff; every probe individually guarded, so a partial
result always lands). Shape: `data.page = "capsweep"` with
`env/features/syntax/storage/ws/worker/canvas/fontface/timer/cloop`.

**wsagent.html — persistent WebSocket eval-RPC agent.** Connects to
`ws://<rig>/ws?role=agent` (a real RFC 6455 endpoint in portal.py,
stdlib-only) and loops `{id, code} -> eval -> {id, ok, result|error,
elapsed}`. Built-ins: `ping`, `caps`, `ls-storage`,
`storage.get/set/del <key> [value]` (localStorage staging with size
report, also exposed as `window.__agent` for eval'd commands); anything
else evals in page scope. Survives applet idle: 10s heartbeats, 75s
receive watchdog, capped auto-reconnect (1s..30s), immediate beat on
visibility change, self-healing re-dial. Telemetry: phases
`boot`/`connect`/`disconnect`/`crash` with channel counters
(`data.page = "wsagent"`, `data.channel`). Operator sides (local-only):

```bash
curl -X POST http://127.0.0.1:8080/rig/ws/send -d '{"code":"caps"}'   # eval on console
curl http://127.0.0.1:8080/rig/ws/state        # agent liveness + reply log
# or attach an interactive console: any WS client to ws://<rig>:8080/ws?role=console
```

**varargs.html — MarkedVector::fill GC-rooting crash oracle (CVE-2023-43000
class), phased.** Verified in our frozen tree
(`vendor/nintendo-oss/.../webkit_3.12.11`): `runtime/ArgList.h:219-228` —
`fill(count, func)` hands the functor the JSValue buffer with NO
`m_markSet` registration (the fix's exact addition) and no zeroing;
`llint/LLIntSlowPaths.cpp:2305-2312` — the varargs checkpoint runs
`loadVarargs` inside that functor; `interpreter/Interpreter.cpp:260-300` —
the copy loop's `object->get()` executes Proxy traps/getters (user JS,
allocations) while the >8-arg heap buffer is unrooted. LLInt is the ONLY
tier on this no-JIT console, and this IS the LLInt slow path. In this
613-era fork `f(...x)` lowers to `OpCallVarargs`
(`bytecompiler/NodesCodegen.cpp:2090-2098`), as do `Reflect.apply` and
`f.apply` — the page exercises apply (engine-agnostic) and spread
(lowering diagnostic). Phase 1 (default, SAFE): pure timing/side-effect
oracle — array/getter-object/Proxy shapes through apply, trap-count
expected-vs-actual (length read + one per index), callee arg-count and
checksum verification, timing samples under interleaved (small)
allocation pressure; a 4th shape records whether spread lowers to
varargs or the iterator protocol. Phase 2 (+gate): escalating GC-pressure
rounds — traps allocate (ropes + ArrayBuffers), side loop churns
4/16/64/256 MiB between applies, run counts and churn size in CFG;
armed-marker per round, `progress` telemetry mid-phase (crash-suffix
oracle like fontchain). Phase 3 (+gate): reserved stub — victim shaping,
READ-ONLY: typed-array victims interleaved in the marshalled args,
byte-for-byte verification after each pressured apply. Telemetry phases
`env`/`progress`/`verdict`/`crash` with `p1.shapes[]`, `p2.rounds[]`,
`p3.runs[]`; verdicts `BASELINE-CONSISTENT`, `DIVERGENCE`,
`PRESSURE-SIGNAL`, `PRESSURE-CLEAN`, `VICTIM-CORRUPTION`,
`PRIOR-RUN-CRASHED`. **PARKED — see the block above.**

**strnorm.html — JSC→ICU int32 length-overflow oracle (CVE-2025-43429
class), phased.** Verified in our tree:
`runtime/StringPrototype.cpp:1952-1963` — `unorm2_normalize(...,
view.length(), ...)` and `:1646-1652` — `u_strToLower/u_strToUpper(...
s.length(), ...)` pass JSC string lengths into ICU's int32 parameters
unchecked, while `JSString::MaxLength == INT32_MAX`
(`runtime/JSString.h:120`). Trigger: rope strings (`'A'.repeat(N)` —
ropes, no materialization) with N climbing toward the 0x3FFFFFF0
boundary. Phase 1 (default, SAFE): length-arithmetic oracle — small safe
N (`CFG.P1_NS`), every op (normalize NFC/NFD, toLowerCase, toUpperCase):
API presence, result-length==N, content spot-checks, repeat-is-rope
timing, and the timing curve vs N (raw samples, bench fits the curve).
Phase 2 (+gate): escalating N ladder (`CFG.P2_LADDER`, 0x10000000 →
0x3FFFFFF0) under a HARD memory budget — before the ladder a doubling
ArrayBuffer probe measures the largest single allocation that succeeds
(capped 1.5 GiB), and a rung runs only if `2*N*1.25 + 64 MiB` fits; any
memory-flavored exception ABORTS the ladder immediately (the applet heap
is finite; telemetry must survive), memory report (budget +
`performance.memory` when present) before/after every run, plus a
between-rungs time cut. Phase 3 (+gate): reserved (length-growth shapes
like NFD doubling, where the int32 overflow actually bites — built only
after phase 2 maps the boundary on-device). Every run reports
`{n, op, repeatMs, elapsedMs, resultLength, contentSpot, exception,
memoryBefore/After}`; verdicts `ARITHMETIC-CLEAN`,
`LADDER-COMPLETE/CLEAN/DIVERGENCE@N`, `ABORTED-BUDGET-AT-N`,
`BUDGET-TOO-SMALL`, `LADDER-TIME-CUT`, `PRIOR-RUN-CRASHED`.
**PARKED — see the block above.**

**pngztxt.html — libpng compressed-ancillary-chunk oracle (CVE-2026-46675
class), phased.** The applet ships libpng 1.6.57 (docs/NDAYS-C-TIER.md
verdict 1); the zTXt/iCCP/iTXt read-after-free is fixed only in 1.6.59 —
one crafted PNG through `<img>` is the whole trigger surface. Delivery:
the page loads `<img>` tags from the rig's own PNG crafter
`GET /rig/png/ztxt?mode=N&seed=N` (portal.py, stdlib zlib; canvas is
never used — it re-encodes and would destroy the chunk framing). Phase 1
(default, SAFE): modes 0-3 (baseline, well-formed zTXt/iCCP/iTXt) —
load/error events, naturalWidth/Height, decode() timing: proves the
compressed-chunk code path executes WITHOUT attacking it
(`PARSE-PATH-LIVE`). Phase 2 (+gate): modes 10-16 — truncated zlib
streams, chunk length past EOF, ~1MiB iCCP profile, empty compressed
data, bad CRC — REPEATS per mode with distinct seeds, armed-marker per
mode, crash-suffix oracle; the crafter ALSO refuses malformed modes
below phase 2 server-side (403 `E_PHASE_GATE`), so the shapes cannot be
fetched even with the page open. Phase 3 (+gate): reserved (heap
grooming around the freed zlib stream). Telemetry: `p1.images[]`,
`p2.rounds[]` with per-image `{mode, seed, outcome, naturalW/H,
decodeMs, totalMs}`; verdicts `PARSE-PATH-LIVE`, `CHUNK-REJECTED`,
`MALFORMED-SURVIVED`, `PRIOR-RUN-CRASHED`.

**freeze.html — freeze/seal-on-private-fields structure oracle
(CVE-2026-20608), phased.** The LIVE pure-interpreter chain verified in
our tree (docs/NDAYS-V2.md row 2): `ObjectConstructor.cpp:785-788`
fast-path freeze → `JSObject.cpp:2616-2621` → `Structure.cpp:844-853`
attribute loop ORs DontDelete+ReadOnly onto EVERY property-table entry
with no private-name exclusion (the `isPrivateName()` idiom exists at
`:1367` but is not consulted), and the corrupted structure is cached as
a reusable transition at `:866-874`. Phase 1 (default, SAFE):
behavioral oracle only — classes with 1/2/4/8 private fields,
`Object.freeze(this)` in constructors, instance-order matrices
(freeze-first/freeze-last/interleaved, 48 instances per run) exercising
get/set/`#x in`/defineProperty/delete; reports any OBSERVABLE attribute
desync (frozen-ness asymmetry between instances — the cached-transition
symptom —, private-field write inconsistency, exception text); a crash
is not expected or required. Phase 2 (+gate): structure-spray
escalation — 24 distinct class shapes per round (unique field
counts/orders via `new Function` factories), freeze-mid-method variants,
transition-table reuse patterns (property churn → freeze → late
instances that must reuse the corrupted transition); armed-marker per
round, progress telemetry. Phase 3 (+gate): reserved (property-offset
confusion probes). Telemetry: `syntax`, `p1.runs[]` (per-instance
observation matrices), `p2.rounds[]`; verdicts `CONSISTENT-FROZEN`,
`DESYNC(n)`, `SPRAY-CLEAN`, `SPRAY-DESYNC(n)`, `UNSUPPORTED`,
`PRIOR-RUN-CRASHED`.

**webp4863.html — libwebp CVE-2023-4863 one-shot status probe,
gate-required from the start.** The applet's libwebp version is
unpinnable statically (the decoder ABI check compiled away the minor
version — docs/NDAYS-C-TIER.md verdict 2); if it is < 1.3.2,
BuildHuffmanTable is a contiguous heap OOB write with fully
attacker-controlled bytes. Unlike every other kit page there is NO free
phase: the single `<img>` load of a staged public-PoC-class lossless
WebP (`/stage/webp4863.webp` — absent → clean `SKIPPED-NO-ASSET`, like
fontchain's crafted font) runs ONLY at rig phase >= 2 (the same
deliberate `/rig/phase` opt-in that arms the other pages' phase 2);
below that it reports `SKIPPED-GATED`. Armed-marker before the load; the
load itself is fully instrumented (naturalWidth/Height, decode() timing,
error outcome). If the load crashes the applet, the armed marker reports
`PRIOR-RUN-CRASHED` on the next load — that crash IS the verdict and
everything after is manual. No further phases by design.

**fontchain.html — CSSFontFace::setStatus UAF harness (CVE-2026-43715
class), PHASED and SAFE by default.** Built from the publicly documented
bug class (Jmesmykil/switch2-captive-portal-research
`cssfontface/WebKit-CSSFontFace-UAF.md`, `PORT.md`,
`ANALYSIS-pac-bypass.md`, `scenario.html`, `arw-final.html`; upstream
ntfargo/CSSFontFace-Exploit) — not copied exploit code. Phase 1
(default): trigger-only crash/no-crash oracle — install `@font-face`
local() rule, force layout, prime `face.loaded`, install a
`FontFace.prototype.then` getter that deletes the rule and flushes layout
reentrantly during `setStatus`, call `face.load()`; per local-font
candidate report fired/survived/status/timings. A crash mid-run leaves
an "armed" localStorage marker the next load reports (`gate.priorCrash`).
Phase 2 (+gate): same trigger with the 0xB8 ArrayBuffer reclaim spray,
scan for the documented signatures (reclaimed buffer's refcount slot
reads 2 / dirty bytes) and dump hits for offset derivation; phase 2B
(needs a crafted font at `/stage/fontchain-r2.otf`): the
`FontFaceSet::load` rule-juggling shape yielding the stale-FontFace +
reclaimed-buffer pair. Phase 3 (+gate): read-only arb-read STUB via
`m_featureSettings` (+0x28/+0x30/+0x34), self-address chain
`m_wrapper`@+0x60 -> `m_backing`@+0x30, optional explicit
`?addr=0x...&len=N` dump — no write/JOP (wkc3 signs data pointers; the
PAC analysis is why this stops at read). wkc3 23.0.1 offsets live in the
page's `CFG` constants.

The phase gate is rig-side and interlocked: `GET /rig/phase` reports it,
`POST /rig/phase {"phase":N}` (local-only) advances it; a `?phase=N`
URL can only LOWER the effective phase, never raise it above the rig
flag. Telemetry: phases `env`/`verdict`/`crash`
(`data.page = "fontchain"`) with `gate`, `p1.candidates[]`, `p2` (+scan
dumps), `p2b`, `p3`, `verdict` (e.g. `TRIGGER-LIVE-SURVIVED`,
`RECLAIM-HIT`, `NO-RECLAIM`, `ARB-READ-STUB-OK`). The launch.py watcher
journals every kit-page POST as a `page_report` event with a per-page
headline summary.

### Session observability (full-fidelity logs, --verbose, /rig/live, session report)

Everything a session produces is persisted to the runs dir with
append+flush, so it survives a crash of any component:

| file | content |
|---|---|
| `rig-<ts>.jsonl` | every `/report` body (full page telemetry envelopes) |
| `access-<ts>.jsonl` | every portal request (`ts/peer/method/host/path/status/bytes/ua/uir`) plus control-plane lines (`kind: phase_gate` with from/to, `kind: swap`) |
| `dns-queries.jsonl` | every DNS query dns.py handled (`ts/client/proto/qname/qtype/verdict/answer/rcode`) — dns.py `--log-jsonl`, wired by launch.py into the telemetry dir |
| `ws-<ts>.jsonl` | every WebSocket frame both directions (`ts/dir/role/peer/opcode/size/preview` first 512B) |

`launch.py --verbose` streams every journal event to the terminal as it
lands — the launcher's TelemetryWatcher tails ALL the files above plus
the portal's live ring, so the one-liners cover the whole session:
`DNS_QUERY [console] ctest.p01... A 192.168.x.x`, `HTTP_HIT [console] GET
/portal 302 0B UA=libcurl(nnNifm)`, `APPLET_ENTRY`, `PAGE_REPORT
[capsweep] phase=full verdict=...`, `PHASE_GATE changed 1->2`,
`WS_AGENT connected`, `WS_EVAL eval#12 ok 3ms`, `SWAP /portal->wsagent`.
Compact, greppable, color when stdout is a tty; the dashboard's own feed
polls are ring-filtered so there is no spinner noise. Default (non-
verbose) keeps the classic quiet behavior.

`/rig/live` (portal, GET, read-only, LAN-ok) is a self-contained
dashboard: polls `/rig/live/feed?since=<seq>` once a second (monotonic
seq over an in-memory ring of the last ~2000 events) and renders a
status strip (uptime, phase gate, current `/portal` page, WS agent
state, console first-seen), a live event table (auto-scroll toggle), and
a verdict panel with the latest headline per kit page.

At clean teardown (and on the SIGINT path) the launcher writes
`<runs>/session-<ts>.md` — a markdown summary generated purely from the
journal + persisted logs: session window, console first-seen, DNS stats
(answered vs NXDOMAIN, unique qnames), HTTP stats by path+UA, applet
entry yes/no, every kit page's final verdict and phase reached, WS eval
stats, phase-gate history, anomalies (held ports, crashed kit pages,
server errors, watcher errors), and a NEXT-STEPS checklist of gated
phases attempted vs remaining. The path is linked from the teardown
printout and recorded in `exit-summary.json`.

### Session journals (launch.py)

Every `launch.py` session writes `tools/webkit-rig/runs/rig-sessions/<ts>/`:

| file | content |
|---|---|
| `config.json` | mode, chosen interface/IP, bind result, ports, pf state, sharing state, platform, argv |
| `events.jsonl` | launcher events: preflight (incl. `preflight_hygiene`), pf anchor load/status, `applet_first_seen`, kit-page `page_report`, `services_stopped`, `ports_released`, teardown |
| `portal.log` / `dns.log` | full service stdout/stderr (access logs included) |
| `telemetry/rig-*.jsonl` | the runs file itself (the console's reports) |
| `telemetry/access-*.jsonl` | every portal request + control-plane lines (see observability above) |
| `telemetry/dns-queries.jsonl` | every DNS query dns.py handled |
| `telemetry/ws-*.jsonl` | every WebSocket frame, both directions |
| `telemetry/session-*.md` | the teardown session report |
| `exit-summary.json` | per-console-IP first-seen state, telemetry line count, teardown results (incl. port-release verification) |

## Automation ladder — where launch.py takes us

`launch.py` (macOS-primary) collapses the rig to one command. What is now
AUTOMATED per session:

1. **Preflight** — macOS check; IPv4 interface enumeration
   (`networksetup -listallhardwareports` + `ifconfig` parsing) with
   interactive pick and `--interface`/`--ip` overrides; STALE-RIG-LISTENER
   HYGIENE (lsof pid map + ps full-command match reaps our leftovers on
   80/443/53/8080/5353, never foreign listeners); high-port bindability
   checks; Internet Sharing state (read-only `defaults read
   …/com.apple.nat`); pf state reported (checked for real, read-only,
   during bring-up).
2. **pf anchor** — services run UNPRIVILEGED on 8080/5353; the
   `com.barbarismjb.rig` anchor (table-less rdr, chosen interface only)
   redirects 80→8080 and 53→5353; load, verify, and teardown touch ONLY
   that anchor.
3. **Services** — portal.py + dns.py supervised (logs into the journal,
   health-checked, SIGTERM-safe teardown, orphan-free); teardown VERIFIES
   the session's ports released (retry loop, warn + journal on holds).
4. **Telemetry hooks** — runs jsonl tailed live; first applet UA → banner;
   every kit-page POST journals a `page_report` event. Page selection is
   the operator's explicit `/rig/swap?name=…` (the `--auto-probe` chain is
   retired — the 32439 detector was FTL-only on a no-JIT console).
5. **Journaling** — everything above lands in `runs/rig-sessions/<ts>/`.

What remains MANUAL (by design — they live on the console or in system
settings the rig must not touch):

- **Router mode:** the console joins the existing LAN and the operator
  sets its DNS manually to the Mac's IP (exact steps printed, detected IP
  included, plus the do-not-test-update warning).
- **Standalone mode:** the Internet Sharing toggle in System Settings
  (TCC-protected; the rig guides and then detects the bridge subnet).
- The one-time `rdr-anchor "com.barbarismjb.rig"` line in `/etc/pf.conf`
  (operator-owned persistent edit) if you want the anchor path live
  without per-session sudo services — see caveats below.

## macOS caveats (learned on macOS 27, this bench)

- **pf anchor isolation vs. evaluation.** macOS evaluates only anchors the
  main ruleset references, and stock `/etc/pf.conf` references only
  `com.apple/*` (its own header warns against flushing the main ruleset —
  Apple services insert anchors dynamically). So loading
  `com.barbarismjb.rig` is safe and isolated, but it stays INERT until
  the main ruleset references it. launch.py verifies both facts (pf
  enabled? anchor referenced?) with read-only sudo after loading and
  degrades honestly: direct privileged bind (one explained sudo) →
  high-port mode. It never runs `pfctl -d`, never loads /etc/pf.conf,
  never edits global state.
- **Internet Sharing DNS proxy conflict.** macOS's sharing stack runs its
  own DHCP + DNS forwarder on the bridge. In standalone mode the console
  MUST use manual DNS to the Mac's bridge IP, or macOS answers instead of
  our dns.py. The launcher prints this as a mandatory step.
- **SSID from the Mac's name.** Internet Sharing broadcasts an SSID
  derived from the Mac's name; it cannot be renamed from the rig.
- **Bridge subnet is detected, never assumed.** macOS defaults the
  sharing bridge to 192.168.2.1 but renumbers on subnet collisions
  (virtualization bridges like bridge100 at 192.168.139.x coexist on this
  bench). `--mode standalone` detects the actual bridge IP and prints it.
- **sw_vers on macOS 27** reports `ProductVersion 27.0` with a `26A428`
  build — harmless here (journal metadata only), noted so nobody
  "fixes" it later.
- **`com.apple.nat` plist may not exist** until Internet Sharing has been
  configured once; launch.py treats "domain not found" as sharing-off.

## Ready-to-go hardware checklist

- [ ] Mac on the LAN (Ethernet or Wi-Fi) with a sane IPv4 on the interface
      the console can reach (`launch.py --mode list` to confirm).
- [ ] Console on stock firmware 23.0.1, LAN SSID saved, no manual DNS
      residue from earlier sessions (Automatic before starting).
- [ ] Mac and console on the same L2 segment (no client isolation /
      guest VLAN blocking console→Mac traffic).
- [ ] Ports free: nothing already listening on 80/53 (checked by the
      launcher; `lsof -nP -iTCP:80 -sTCP:LISTEN` to pre-verify), 8080/5353
      bindable.
- [ ] sudo available for the operator (anchor load and/or direct-bind
      fallback; every use is explained before the prompt).
- [ ] Python 3.8+ present (`python3 tools/webkit-rig/launch.py
      --self-test` passes); `node` present for the probe-page syntax check
      in the suite (skipped gracefully without it).
- [ ] A second LAN machine (phone/laptop) handy to verify legs with
      dig/curl when something doesn't light up.


## From test rig to exploit delivery rig

The rig is deliberately shaped so the entry path never changes when the
exploit lands — only the served content does:

1. **Now:** probe page at `/portal`, telemetry at `/report`, DNS hijack
   of the conntest set. Proves entry, fingerprints the runtime.
2. **Next:** `/stage/*` already serves arbitrary staged files (typed
   correctly for `.js/.wasm/.otf/.bin/…`) — future payload stages,
   heap-groom assets (e.g. the GPOS `@font-face` class of probes), and
   offset tables fetch from there exactly like the probe fetches `/report`.
   `/ws` is now a real WebSocket bridge (stdlib-only RFC 6455): the
   wsagent page (`pages/wsagent.html`) provides the live JS eval/replay
   control channel, driven by a `role=console` client or the local-only
   `/rig/ws/send` curl path.
3. **Then:** `/portal` serves the civshim-webkit payload (built by
   `engine/build-payload.cjs` from `payloads/`, stage-2 chunks via
   `/stage/`), turning the rig into the standing delivery mechanism for
   the WebKit chain — the same DNS→302→applet flow, no requalification of
   the entry surface needed.

Operational discipline stays as in `tools/webkit-rig/README.md`: LAN-only,
no upstream DNS while rigged, restore Automatic DNS + success-mode cleanup
after every session, console pinned to 23.0.1.
