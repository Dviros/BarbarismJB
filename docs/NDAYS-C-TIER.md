# NDAYS-C-TIER — bundled C-library audit of the browser applet (2026-11-11)

Companion to `NDAYS-V2.md` (which audited WebCore/JSC/WTF only). The
C-library tier sits directly on attacker-controlled bytes — fonts we
serve, images we serve, compressed responses we serve. All versions
pinned from the fw-23.0.1 dump (`wkc0`/`wkc1`/`wkc4` NSO rodata +
dynsyms; never executed), cross-checked against
`vendor/nintendo-oss/.../WebKitLibraries_3.12.11/` where source ships.

## Version census

| Lib | Version | Where | Reachable from portal page |
|---|---|---|---|
| libpng | 1.6.57 | wkc0/wkc1 strings | **HIGH** — `<img>` |
| libjpeg-turbo | 3.0.x | wkc0 strings | HIGH — `<img>` |
| libwebp | **unpinned** (ABI check compiler-folded; see below) | wkc0 symbols | HIGH — `<img>` |
| cairo | 1.18.4 | wkc1 + OSS libs | HIGH — Canvas 2D (readback proven) + SVG |
| **wkc4 `libfont`** | proprietary Nintendo OT parser (cmap/GSUB/GPOS/kern/post) | wkc4 strings | **HIGH — raw @font-face bytes** (`FontCustomPlatformDataWKC.cpp:82-93`); NO WOFF/WOFF2 anywhere (raw scan, 0 hits) |
| ICU4C | **62.2 (Apr 2019)** | wkc0 strings + 89 icu::* dynsyms | HIGH — Intl.* + all text layout |
| cURL | 8.20.0 | wkc0 strings | transport for fetch/XHR |
| zlib | 1.3.2 | wkc0 strings | PNG IDAT inflate |
| nghttp2 | 1.68.1 | wkc0 strings | **DEAD from portal** (h2 only over TLS: `ResourceHandleManagerWKC.cpp:588`) |
| nghttp3 / ngtcp2 | 1.13.1 / 1.18.0 | OSS headers + strings | DEAD (HTTP3 disabled: `:306` `ENone`) |
| SQLite | 3.50.4 | wkc0 strings | DEAD (WebSQL off: `RuntimeEnabledFeatures.h:296`, no setter) |
| brotli | ~1.1.0 | conditional | only if cruiser sets accept-encoding (runtime probe) |
| freetype / harfbuzz / fontconfig | NOT LINKED (OSS libs ship but zero symbols in any NSO) | — | font engine is wkc4 libfont instead |
| OpenSSL | 3.5.7 | wkc0 | skipped (current) |

## Verdicts

1. **CVE-2026-46675 (libpng ≤1.6.57, read-after-free in compressed
   ancillary chunks zTXt/iCCP/iTXt) — LIVE.** Fixed only in 1.6.59
   (2026-09-30). Trigger: one crafted PNG via `<img>`; the EOF handler
   reads the zlib stream pointer after free. Read-after-free ⇒ leak /
   crash primitive; single-tag, no state machine — easier to stage than
   the font UAF.
2. **libwebp CVE-2023-4863 (critical, BuildHuffmanTable contiguous heap
   OOB write) — UNCERTAIN.** Version unpinable from strings; the decoder
   ABI check compiled to `and w9,w1,#0xFFFFFF00; cmp w9,#0x200`,
   erasing the minor version (0x0209 vs 0x021x indistinguishable).
   Resolution paths: (a) static — disassemble BuildHuffmanTable (static
   fn, reached via WebPINewDecoder call graph) and match the 1.3.2
   bounds-check shape; (b) runtime — one public 4863 PoC image on
   `<img>` in the first applet session (crash = the strongest primitive
   class in the whole program: contiguous heap OOB write, 100%
   attacker bytes). Circumstantial: every OTHER wkc0 lib is 2025-26
   current, which argues ≥1.3.2 — but ICU 62.2 breaks the pattern.
3. **CVE-2026-20608 (JSC freeze/seal on private fields) — LIVE, full
   caller chain verified** (see NDAYS-V2 row update): pure interpreter
   path, `Object.freeze(this)` in a constructor → `Structure.cpp:846-853`
   attribute loop with no private-name exclusion → DontDelete+ReadOnly
   OR'd onto private-symbol entries, and the corrupted structure is
   **cached as a reusable transition** (`Structure.cpp:868-874`).
   JS-only trigger; crash-shaping needs PoC iteration.
4. **cURL 8.20.0 — clean for the portal lane**: every post-8.20
   memory-corruption CVE is h2/TLS-gated (18924, 92392, 10536) ⇒ dead
   from plain HTTP; leftovers are cookie/HSTS logic bugs + a DoS loop.
5. **zlib 1.3.2 — clean for the lane**: the 1.4 fixes (inflateSync/
   Prime/Back, gz* OOB) never touch the plain `inflate()` path libpng
   and HTTP-gzip use.
6. **cairo 1.18.4 — clean**: CVE-2025-50422 sits in cairo-ft-font.c and
   the freetype backend is not compiled into wkc1.
7. **libjpeg-turbo 3.0.x — clean** (CVE-2023-2804 fixed in 3.0.0).
8. **ICU 62.2 — no feasible known CVE** (10531 needs ≥2^30-char strings
   — infeasible in ~341 MiB heap; 30535 attribution murky; 5222 is a
   build tool), but **7 years of un-CVEd OSS-Fuzz backlog with no
   source** = standing lane, trivially reachable via Intl/any text.

## Rewired font lane (important correction)

freetype/harfbuzz/fontconfig are NOT the applet's font engine. Remote
`@font-face` bytes go raw into **wkc4 `libfont`** — first-party Nintendo
OT parsing (cmap/head/hhea/maxp/OS-2/post/name/kern/GSUB/GDEF/GPOS per
its debug strings). The proven CVE-2026-43715 chain lives one layer
above it (WebCore CSSFontFace state), but the same delivery path feeds
a proprietary, publicly-unaudited parser. If 43715's reach ever narrows,
libfont table-parsing is the adjacent first-party surface.

## Kit order impact

- `pngztxt` oracle page (46675): craft/serve malformed zTXt PNG → crash
  oracle — cheap, add before first session.
- `freeze` oracle page (20608): pure-JS structure-corruption oracle with
  instance/structure iteration patterns from the chain above.
- `webp-4863` one-image probe: stage a public PoC image; single `<img>`.
- All remain blocked behind Wall 0 (see `FOCUS.md`).

## libxml2 closure record (2026-11-11, full audit by dedicated pass)

**Pinned: libxml2 2.15.x** (2.15.0–2.15.4; string-forensic chain: ≥2.14.0
via parser.c `Maximum number of attributes exceeded` @wkc0 mod+0x6e3b06
and the reworded depth error @mod+0x6b352a; ≥2.15.0 via 3/3 SAX2.c-only
strings + 26/27 encoding.c HTML5-alias strings; point release
indistinguishable at string level — and nothing in 2.15.1→2.15.4 makes
pinning it worthwhile). Bundle context (OpenSSL 3.5.7, Jun 2026) →
2.15.2/.3/.4 plausible.

**Reachable surface (all portal-controllable):** navigated XML docs
(`application/xml`), SVG, `DOMParser.parseFromString`, XHR
`responseXML`, XML fragments via innerHTML, and same-origin external
entities (`XML_PARSE_NOENT|HUGE` on every path —
`XMLDocumentParserLibxml2.cpp:547-588`). **Not compiled/called:**
XPath (error table absent, xpath.c not linked), XSLT (re-confirmed:
zero xslt* symbols), HTMLparser, schemas/RelaxNG/c14n/catalogs.

**CVE diff 2.15.1→2.15.4 (the only live window): zero live
memory-corruption candidates.** The single WebKit-reachable security fix
in the window — CVE-2026-6732 (xmlParseReference closure confusion, fixed
2.15.3) — is **neutralized on this engine**: WebKit's SAX handlers treat
the closure AS the ctxt (`ctxt->_private`, `:1051-1055`) and libxml2's
`userData = userData ? userData : ctxt` makes buggy and fixed calls pass
the identical pointer. Everything else in the window: DoS-only
(parent-walk hang), >2 GB-infeasible, needs attacker catalogs, or sits in
uncompiled components.

**Residual:** the cheap aliasing oracle (DOCTYPE with internal entity
whose replacement text has leading/trailing text children — any crash
falsifies the closure proof and reopens the lane) + the hang class.
**Lane parked; fontchain/43715 remains the primary font-adjacent attack.**
