# Backport check — the two candidate ARW bugs in the wkc3 engine (fw 23.0.1)

Date: 2026-11-10. Executes the checks specified by `docs/WEBKIT-NDAYS.md`
§4.3(3) / §3.1.5 / §3.2.3 against the dumped wkc3 binary
(`<FW_DUMP_ROOT>/040000000000085d/wkc3`,
read-only, never executed; disassembly rizin 0.9.1 on the decompressed
segments; upstream ground truth fetched from the WebKit GitHub mirror at
tags `webkitgtk-2.39.1` (fork point, VULNERABLE for both bugs),
`webkitgtk-2.40.0` (still vulnerable), `webkitgtk-2.40.5` / `2.42.0`
(both fixes landed). Offset conventions as WEBKIT-ANALYSIS.md: `text+X` =
offset in the decompressed wkc3 `.text` (0x1957018 bytes); `mod+X` =
offset in the flat module image (ro at mod+0x1958000).

---

## VERDICTS (the two lines that gate the plan)

1. **CVE-2023-32439 (DFGClobberize `EnumeratorNextUpdateIndexAndMode` /
   `HasIndexedProperty` HeapLocation collision): INCONCLUSIVE by static
   binary fingerprint** (method below). The vulnerable-at-fork-point
   source-level presence verdict (NDAYS §2.2) stands; the per-line binary
   divergence check NDAYS §3.1.5 demanded could **not** be closed offline.
   Confidence in the inconclusiveness itself: high (8 independent search
   strategies, all negative or false-positive; reasons documented).
   The rig runtime trigger is now the decisive gate for this bug.

2. **Enki `JSObject::definePropertyOnReceiver` prototype bug:
   FIXED — the mid-2023 guard IS present in wkc3 (backported by
   Nintendo)**, i.e. the fork-point-vulnerable shape was patched even
   though the fork predates the upstream fix. Confidence: **high** (the
   fix's call shape located and matched at two sites; every observable
   that differs between vulnerable and fixed upstream resolves in the
   fixed direction; the pre-fix alternative was ruled out against
   2.39.1/2.40.0 sources). The published Enki trigger
   (`super.prototype = …` on a class extending `Function`) is closed.

Net effect on the plan: of the "two CONFIRMED-PRESENT" candidates in
WEBKIT-NDAYS §2.1, #2 is now FIXED/absent in wkc3 and #1 carries an open
static caveat — the WebKit host plan's n-day supply narrows to
CVE-2023-32439, gated by the rig probe.

---

## 1. Upstream ground truth (fetched 2026-11-10, raw.githubusercontent.com)

### 1.1 CVE-2023-32439 fingerprints

`dfg/DFGClobberize.h` at `webkitgtk-2.39.1` lines 366–413 (identical at
2.40.0) — the vulnerable merged case:

```cpp
case EnumeratorNextUpdateIndexAndMode:
case HasIndexedProperty: {
    if (node->op() == EnumeratorNextUpdateIndexAndMode) { …OwnStructureMode / IndexedMode checks… }
    read(JSObject_butterfly);
    ArrayMode mode = node->arrayMode();
    switch (mode.type()) {
    case Array::ForceExit: write(SideState); return;
    case Array::Int32: … def(HeapLocation(HasIndexedPropertyLoc, IndexedInt32Properties, varArgChild(0), varArgChild(1)), LazyNode(node)); …
    case Array::Double:  … def(HeapLocation(HasIndexedPropertyLoc, IndexedDoubleProperties, …)); …
    case Array::Contiguous: … def(HeapLocation(HasIndexedPropertyLoc, IndexedContiguousProperties, …)); …
```

Fixed (2.40.5 and 2.42.0, line 402 at 2.42.0):

```cpp
LocationKind locationKind = node->op() == EnumeratorNextUpdateIndexAndMode ? EnumeratorNextUpdateIndexAndModeLoc : HasIndexedPropertyLoc;
… def(HeapLocation(locationKind, IndexedInt32Properties, …)) …
```

Derived numeric fingerprints (from `dfg/DFGHeapLocation.h`,
`dfg/DFGAbstractHeap.h`, `dfg/DFGNodeType.h` at the same tags):

- LocationKind @2.39.1: `HasIndexedPropertyLoc = 11`; the fix **inserts**
  `EnumeratorNextUpdateIndexAndModeLoc` immediately *before* it (diff
  hunk `48a49` of DFGHeapLocation.h), so fixed = new kind 11,
  `HasIndexedPropertyLoc` 11→**12**, every later kind shifts +1.
- AbstractHeapKind (unchanged by the fix, verified by diff 2.39.1↔2.42.0):
  `Butterfly_publicLength=4`, `Butterfly_vectorLength=5`,
  `JSCell_structureID=10`, `JSObject_butterfly=12`, `NamedProperties=15`,
  `IndexedInt32Properties=16`, `IndexedDoubleProperties=17`,
  `IndexedContiguousProperties=18`, `SideState=38`. `AbstractHeap` is one
  `int64_t` (`kind | isTop<<14 | payload<<15`), so a plain heap is its
  kind number.
- NodeType @2.39.1 (397 ops): `HasIndexedProperty=354 (0x162)`,
  `EnumeratorNextUpdateIndexAndMode=356 (0x164)`,
  `EnumeratorNextExtractMode/Index=357/358` (their own merged
  `def(PureValue)` case), `GetPropertyEnumerator=355`.
- Compiled discriminators: **vulnerable** = def sites materialize
  `HeapLocation{u32 kind=11 @+0; u64 heap∈{16,17,18} @+8; base @+0x10;
  index @+0x18}` (kind is a *constant* at three sites); **fixed** = kind
  computed as a select between 11 and 12 (`csel`/branchy `movz #0xb` /
  `movz #0xc`) feeding the same three def sites, plus a re-test of
  `node->op() == EnumeratorNextUpdateIndexAndMode`.
- The def-carrying instantiations upstream are in `dfg/DFGCSEPhase.cpp`
  (LocalCSE `def → m_maps.addImpure(location, value)`; GlobalCSE
  `def → findReplacement(location)` / `availableAtTail.add(location,
  value)` — `dfg/DFGClobberize.cpp`'s own 4 entry points use read/write/
  NoOp or register-only overlap functors).

### 1.2 definePropertyOnReceiver fingerprints

`runtime/JSObject.cpp` @2.39.1 lines 891–918 (vulnerable; 2.40.0
identical) vs 2.40.5/2.42.0 (fixed). Deltas that are observable in a
binary:

| element | vulnerable (2.39.1/2.40.0) | fixed (2.40.5/2.42.0) |
|---|---|---|
| receiver proxy test | `type() == PureForwardingProxyType` (JSType 32) | `type() == GlobalProxyType` @2.42.0 = same numeric slot 32 @2.40.5 |
| outer guard | `slot.isTaintedByOpaqueObject() \|\| slot.context() == ReflectSet(3)` | taint ‖ methodTable≠, **ReflectSet check deleted** |
| inner guard | `methodTable()->defineOwnProperty != JSObject::defineOwnProperty` → Slow | same compare **guarded by `mightBeSpecialProperty(vm, type, uid)`** |
| `mightBeSpecialProperty` | does not exist | JSType switch: ArrayType(36)/DerivedArrayType(37)→`uid==propertyNames->length`; JSFunctionType(26)→uid∈{length,name,prototype}; default→true |
| getter-setter flag | `hasCustomGetterSetterProperties()` (single bit) | `hasAnyKindOfGetterSetterProperties()` (two adjacent bits, `tst #3`) |

MethodTable layout @2.39.1 (`runtime/ClassInfo.h`): `defineOwnProperty`
is entry 12 (offset 0x60 inside `MethodTable`; MethodTable at
ClassInfo+0x30 → pointer slot ClassInfo+0x90); entries are
`WTF_VTBL_FUNCPTR_PTRAUTH_STR("MethodTable.<name>")`, so the constant
side of the compare is **PAC-signed (pacia) with a per-name
discriminator** in this build.

---

## 2. Bug 2 execution — verdict FIXED (high confidence)

### 2.1 Locating the code

`F:/BrowserEngineRelease/Source/webkit/JavaScriptCore/runtime/JSObject.cpp`
exists in wkc3 rodata at **ro+0x5bbf58 (mod+0x1F13F58)** with 24 text
xrefs — but the assert strings turned out to be emitted from inlined
code, so the TU was located structurally instead. The LLInt
`put_by_id`-family slow-path handler (bytecode-opcode dispatch at
text+0x8d518: `ldrb w9,[x1]; cmp w9,#0x84; cmp w9,#0x86`) inlines the
whole `putInlineSlow` + `definePropertyOnReceiver` chain in one function
**text+0x8d4a0…0x91bf0**.

### 2.2 The matched fingerprints (all offsets in decompressed `.text`)

The definePropertyOnReceiver guard, **text+0x8d7d4–0x8d868**:

```
0x8d7d4  ldrb w21,[x23,#5]        ; receiver->type()  (JSCell type byte @+5)
0x8d7dc  cmp  w21,#0x1a           ; == 26 JSFunctionType  -> 0x90734
0x8d7e4  cmp  w8, #0x20           ; == 32 PureForwardingProxyType -> 0x90e5c
         …                        ; structure() decode: [x23]=structureID,
                                  ; table [x20+0x100/0x110], eor-masked ptr -> x24
0x8d80c  ldrb w8,[x24,#0x16]; tbnz w8,#4, slow   ; structure flag
0x8d828  cmp  w21,#0x1a ; b.eq 0x8d86c           ; JSFunctionType BYPASSES the
                                                  ; methodTable compare  <-- fix semantics
0x8d830  …structure flag checks -> 0x9003c (slow)
0x8d84c  ldr  x8,[x24,#0x40]      ; Structure->classInfo
0x8d850  ldr  x8,[x8,#0x90]       ; ClassInfo+0x30 (MethodTable) + 0x60
                                  ;  = methodTable->defineOwnProperty (entry 12)
0x8d854  adrp x16,0x34c000 ; add x16,x16,#0x7a0  ; &JSObject::defineOwnProperty
                                  ;  = text+0x34c7a0
0x8d85c  mov  x17,#0xe443         ; PTRAUTH discriminator "MethodTable.
0x8d860  pacia x16,x17            ;  defineOwnProperty" (ClassInfo.h macro)
0x8d864  cmp  x8,x16 ; b.ne 0x9003c               ; != -> definePropertyOnReceiverSlow
0x8d86c  … getDirectOffset chain; ldr w9,[x24,#0x14]; tst w9,#3   ; <-- combined
                                  ; hasAnyKindOfGetterSetterProperties (2 bits),
                                  ; then CustomValue check + putInlineFast tail
```

The special-property guard helper, **text+0x344400** (called from the
JSFunctionType branch at 0x90758; other call sites 0x344214, 0x351710,
0x3521b0, 0x15cf45c = the other put-family entry points where the same
guard is needed):

```
0x344424  add  x20,x1,#0x9c70     ; vm.propertyNames (embedded at VM+0x9c70)
0x344448  ldr  x9,[x20]
0x34444c  ldr  x11,[x9,#0x7b0] ; cmp x3,x11 ; b.eq 0x344578   ; uid vs name #1
0x344458  ldr  x10,[x9,#0x668] ; cmp x3,x10 ; b.eq 0x344538   ; uid vs name #2
0x344464  ldr  x9,[x9,#0x708]  ; cmp x3,x9  ; b.eq 0x34449c   ; uid vs name #3
0x344578  ldrb w11,[x10,#0x36]  ; structure->indexingType
0x344580  lsl  w11,#1,w11 ; tst w11,#0x78007                  ; array-shape mask
                            ; (the ArrayType/DerivedArrayType "only length is
                            ;  special" variant of the fixed guard)
```

i.e. a uid-vs-{length,name,prototype} triple compare against
`vm.propertyNames` plus the array indexing-type mask — exactly the
`mightBeSpecialProperty` fix family (upstream returns bool; wkc3's
outlined helper returns a 3–4-valued enum (`csel w0,w8,wzr,lo` over
`w8−1≤2`) and also folds the caller's structure-flag branches — an
IPO/outline of the always-inline helper across its 5 call sites, not a
verbatim 2.42.0 compile).

### 2.3 Why every alternative is excluded

- The **vulnerable** shape (2.39.1/2.40.0 sources verified above) has no
  JSFunctionType branch, no propertyNames-uid compare, keeps the
  `slot.context()==ReflectSet(3)` test at the guard, and uses a
  single-bit getter-setter flag. wkc3 contradicts it on all four
  observables: JSFunctionType branch present (0x8d7dc/0x8d828), the
  triple propertyNames compare present (0x344400), no ReflectSet test at
  the guard (cmp#3 exists only in putInlineSlow's CustomValue path
  elsewhere in the handler), and `tst #3` combined flag (0x8d890).
- The fragment cannot be a devirtualized `JSFunction::put` fast path:
  the `pacia`-signed compare (discriminator 0xe443) is against
  **MethodTable.defineOwnProperty**, a compare unique to
  definePropertyOnReceiver (JSFunction::put never compares
  defineOwnProperty), followed by getDirectOffset + putInlineFast —
  definePropertyOnReceiver's exact tail.
- The `type()==8` check inside the helper and the fork's local JSType
  numbering are immaterial: the three propertyNames uid compares and the
  array-mask branch are the load-bearing semantics.

**Verdict: FIXED — the 16.5.1-era RSR guard was backported into the
Nintendo 2.39.1-window fork. The Enki trigger (converting
`Function.prototype`-derived non-configurable `prototype` into a
configurable OOL property via `super.prototype = …`) routes to
`definePropertyOnReceiverSlow` (text+0x9003c) and no longer reaches
`putInlineFast`.**

---

## 3. Bug 1 execution — verdict INCONCLUSIVE (static)

Everything below was run read-only against
`/tmp`-decompressed `wkc3.text.bin` (26 570 776 bytes); every candidate
was disassembled and read before being rejected.

1. **Op-compare anchors** (`cmp #356` / `cmp #354`, 32-bit, whole text):
   3 + 7 sites. All are outer op-dispatch trees in other functions
   (examined: text+0x372c34 and its twin text+0x14faf2c — host functions
   text+0x3726d0..0x372c68 / text+0x14fac60..0x14fb16c, register-only
   per-case bodies = the `AbstractHeapOverlaps`-functor clobberize
   instantiations with no def sites; text+0xa27ac0 — a constant-producing
   op switch). No *inner* `if (node->op() == EnumeratorNextUpdateIndexAndMode)`
   re-test was found anywhere — expected inside every def-carrying
   instantiation regardless of vuln/fixed, which suggests the fork's
   NodeType numbering (like its option set, W1 §2.2) has drifted from
   2.39.1, so these constants are unreliable anchors.
2. **Heap-constellation windows** ({16,17,18} producers, window 0x180 and
   0x400, movz + ORR-bitmask, with/without corroboration 4/5/38):
   21–39 clusters, each manually resolved to a false positive: ICU
   `unum_*` calls (PLT text+0x194ea68 = `unum_setAttribute`, GOT
   0x25893a8), rodata string-table initializers (the text+0x658xxx–
   0x65cxxx region — `bl` with `w1` = *string length*, which mimics kind
   constants), small-int mapper switches (`mov w0,#imm; ret` tables), and
   ByteCodeParser node-construction code (text+0x992xxx).
3. **Jump-table signature** (a clobberize op-switch table must have
   entry[354]==entry[356] — the merged case label — with
   entry[357]==entry[358] and ≠entry[355]): all 388 jump tables in .ro
   decoded via the `adrp+add / ldrsw …,lsl #2 / adr / br` idiom, tested
   for shifts −8…+8. Seven signature hits, all disassembled and rejected
   (value mappers, node construction, WTF vector filters).
4. **Vulnerable def-site stack shape** (`movz w,#0xB` stored at struct+0
   with a 16/17/18 immediate stored at struct+8; bases sp and x29; kind
   store width relaxed to 64-bit): **zero** genuine sites in the entire
   text (only degenerate same-register pairs).
5. **Fixed-shape select** (32-bit `csel` with both operands movz'd to 11
   and 12): 13 sites; every one is a 2-D selector among {11,12,14,15}
   driven by a `tst #0x20000000` flag in WKC selector code (e.g.
   text+0x23ae5c, text+0x249f08, text+0x143f8ec), none in an
   array-mode/op-dispatch context.
6. **OwnStructureMode prelude triple** (reads {10,12,15} adjacent —
   present in both vuln and fixed): 7 windows, all string-length or
   mapper false positives.
7. **Node-op name table**: `"HasIndexedProperty"` /
   `"EnumeratorNextUpdateIndexAndMode"` dump strings are absent from
   rodata (graph-dump `printInternal` dead-stripped — also kills the
   `HasIndexedPorpertyLoc` typo-string shortcut), so table-order-based
   op-number recovery is unavailable.
8. **Option-read anchoring** (`validateGraph` at cfg+0x1e8 etc.):
   37 `ldrb #imm` sites, none provably anchored to the g_jscConfig slot
   (the Config is reached via addressing the ldrb scan cannot trace
   generically).

Why the def sites were not findable (assessment, not proof): the
def-carrying instantiations live in the DFGCSEPhase TU, whose
`def` functors (`addImpure`, `availableAtTail.add`) are HashMap ops;
if clang SROA'd the 32-byte `HeapLocation` completely into hash/equality
register operations, no kind/heap *store* pattern survives, and small
register immediates (11/12/16/17/18) are unmatchable in a 26 MB text
without an anchor. Combined with plausible fork drift in both the
NodeType and LocationKind numberings (the option census already showed
the fork is not byte-identical to 2.39.1), the static check is not
closable with the dump alone under the mission's retry budget.
**Per the ≤3-retries rule: INCONCLUSIVE.** Nothing found contradicts
vulnerable-at-fork-point; nothing confirms it per-line either.

---

## 4. Impact on the ranked n-day list (WEBKIT-NDAYS §2.1/§2.3)

- **Candidate #2 ("clobber-the-world" prototype bug): REMOVE from the
  attackable set.** Presence downgraded from CONFIRMED-PRESENT to
  **FIXED-in-wkc3** by §2 above. The §3.2 porting plan (Spread/getter
  confusion PoC) is cancelled — its entry condition (unguarded
  `definePropertyOnReceiver` fast path for `super.prototype`) no longer
  exists in this engine.
- **Candidate #1 (CVE-2023-32439): retains rank 1**, but its "presence
  confirmed" status reverts to *fork-point source shape + machinery
  compiled in* (NDAYS §2.2) with the per-line binary check **open**
  (§3 above). The NDAYS §4 open-question list's item 3 is now answered
  for one of its two halves (prototype bug: backported; clobberize fix:
  unresolved).
- The fuzzing recommendation in NDAYS §2.3/§3.3 shifts weight to the
  clobberize/HeapLocation family only; the
  definePropertyOnReceiver-watchpoint-miss family is closed in this
  build and should be dropped from differential-fuzz targets.
- Everything else in the table is unchanged (ABSENT/UNKNOWN verdicts
  were not re-examined; none is affected by these two results).

## 5. What the rig-side runtime trigger should assert first

1. **CVE-2023-32439 miscompile probe (now the decisive gate).** Host the
   NDAYS §3.1.2 telemetry page on the captive-portal rig: one hot
   function containing a `for (let k in arr)` over an Int32 (then
   Double) array in IndexedMode plus `k in arr` at index 0, driven past
   the stock FTL thresholds (1000/100 000, NDAYS §1.2). **First
   assertion: the `in` result is always strictly boolean-typed**
   (a non-boolean/odd value = GCSE substitution reproduced). Second: a
   tier-up latency spike (~10⁵ invocations) proving FTL compile
   happened. No crash needed; either result closes the INCONCLUSIVE
   verdict in one run (fixed behavior ⇒ the backport exists; miscompile
   ⇒ vulnerable shape confirmed at runtime).
2. **Negative control on the same page:** the (now known-fixed) Enki
   trigger — `class F extends Function {}; super.prototype = {get x(){…}}`
   then spread — should behave spec-correctly (no configurable-OOL
   `prototype`); asserting this doubles as an end-to-end confirmation of
   the §2 backport finding and costs one extra probe.
3. If ARW is reached: per NDAYS §1.5, the first native assertion remains
   the JIT-pool permission probe (RWX vs RW/RX dual-map) at
   `wkc2!wkcMemoryExecutableMallocPeer`.

## 6. Reproduction

```sh
# decompress (scratch, outside the dump):
python3 -I /tmp/bc_scratch/scripts/decomp.py          # -> /tmp/bc_scratch/out/wkc3.{text,ro,data}.bin
# bug-2 evidence:
rizin -q -n -a arm -b 64 -e scr.color=0 \
  -c 'pd 40 @ 0x8d7d4' /tmp/bc_scratch/out/wkc3.text.bin   # guard + signed methodTable cmp
rizin -q -n -a arm -b 64 -e scr.color=0 \
  -c 'pd 30 @ 0x344400' /tmp/bc_scratch/out/wkc3.text.bin  # propertyNames uid triple
# PLT identity of a rejected anchor:
python3 -I /tmp/bc_scratch/scripts/resolve_imports.py 0x194ea68
# upstream ground truth:
# raw.githubusercontent.com/WebKit/WebKit/<tag>/Source/JavaScriptCore/
#   dfg/DFGClobberize.h  dfg/DFGHeapLocation.h  dfg/DFGNodeType.h
#   dfg/DFGAbstractHeap.h  dfg/DFGCSEPhase.cpp
#   runtime/JSObject.cpp  runtime/JSObject.h  runtime/ClassInfo.h
#   runtime/JSType.h  runtime/JSPropertyNameEnumerator.h
# (tags webkitgtk-2.39.1 / 2.40.0 / 2.40.5 / 2.42.0)
```

## 7. Sources

- Upstream WebKit tags as in §1 (fetched 2026-11-10).
- Local: `docs/WEBKIT-ANALYSIS.md` (W1 fork fingerprint, §2), `docs/WEBKIT-NDAYS.md`
  (§1 option decode, §2 candidate table, §3.1.5/§3.2.3 the checks executed here),
  `tools/jsc_options.py` / `tools/webkit_version.py` (NSO decode, adrp/bitmask helpers).
- Enki writeup and pksecurity/shxdow 32439 RCAs as cited in WEBKIT-NDAYS §7.
