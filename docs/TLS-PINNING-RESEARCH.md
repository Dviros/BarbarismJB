# TLS-PINNING-RESEARCH — Switch 2 TLS trust validation (fw 23.0.0)

Researched 2026-11-10. Full findings from the reborn research wave.

## Executive summary — two assumptions overturned

1. **The TLS stack is Mozilla NSS, not mbedTLS** (switchbrew SSL services:
   the ssl sysmodule "implements client-mode TLS using NSS"). Attack surface
   = NSS cert verification (CERT_VerifySignedData, quickder DER decoder),
   not mbedTLS x509_crt.
2. **The CA store is NOT in sysmodule romfs** — it's the **CertStore system
   data title** (`0100000000000000801`), files `/ssl_TrustedCerts.bdf`,
   `/ssl_Crl.bdf`, `/ssl_CaFingerprints.bdf`. Format documented (magic
   `sslT`, entries {Id, TrustedCertStatus, size, offset}; status 1 =
   EnabledTrusted). Explains cert_scan finding zero CA strings in ExeFS.

## Key facts

- Every ISslContext uses the CertStore; **no SPKI pinning for our target
  clients** (only pins: netdev relay hosts). Trust = chain to store roots.
- VerifyOption default 0x3 (PeerCa|HostName|DateCheck); verification can only
  be disabled by the calling process (SkipDefaultVerify / debug flag), never
  from the network.
- dauth is **mutual TLS** (per-device client cert via RegisterInternalPki).
- Built-in roots: NintendoCAG3, NintendoClass2CAG3, Nintendo Root CA G4 +
  ~60 public roots. Our endpoints chain to Nintendo CA G3 (kinnay wiki).
- 7-byte alert = 5B record + 2B alert; description byte distinguishes
  unknown_ca (48) from parse failures (42/45/46) — still worth logging once.

## Prior art

- **kinnay June 2025** (HackerOne 3174987): ImportServerPki SKID-confusion
  TLS bypass — the only public stock-console bypass. **Fixed in 20.2.0**
  (now also CERT_CompareCerts). Patched on our fw.
- **CVE-2021-43527** (NSS heap overflow in cert verify, MITM-triggerable):
  fixed 13.2.1 — but proves the server-cert path is a reachable bug surface.
- **network_mitm** (nookingtons): Atmosphère sysmodule, ssl IPC interception
  — requires code exec.
- No pure-network MITM of stock Switch system traffic exists publicly.
- pepsipu's blog: zero TLS content — his chain is entirely local
  (SmileBASIC OOB → fs Path::Normalize → ldr ExeFS-swap). The ExeFS-swap
  primitive is the TLS-bypass delivery vehicle.

## Ranked strategies

| # | Strategy | Needs |
|---|---|---|
| A | **Patched ssl sysmodule via ldr ExeFS-swap** (verify-off NOP or root injection) — kills pinning for ALL nnSdk clients; then plain python MITM | elevation (SmileBASIC/chain) |
| B | **CertStore .bdf edit** — append our root as EnabledTrusted; format fully documented; needs SYSTEM-partition write + NCA hash repair | fs write |
| C | **NSS 0-day hunt** — grep dumped ssl binary for vendored NSS version, diff upstream, fuzz malformed chains from the rig (CVE-2021-43527 class) | nothing — start tonight |
| D | Dead ends: ImportServerPki SKID (patched), CVE-2023-0767 (import path), user CA (none), browser cacerts.pem (separate trust domain) | — |

**Browser track note:** BrowserCoreDll's `openssl_peer/cacerts.pem` (romfs,
file-based) is a SEPARATE trust domain from nnSdk/CertStore. The captive
applet (WifiWebAuth) is the bridge: it loads OUR plain-HTTP page regardless
of CertStore — which is why the captive path is the entry, and why the
applet gate (see APPLET-GATE-RESEARCH.md) is the actual wall, not TLS.

## Sources

switchbrew SSL services / Title list / Switch System Flaws · Reversing.Live
sslbypass writeup + HackerOne 3174987 · kinnay NintendoClients wiki +
issue #32 · nookingtons/network_mitm · pepsipu ns2jb blog · NVD CVE-2023-0767


## Cert-fuzz round 1 results (live console, 2026-11-10 23:59-00:02)

Posture: success profile + catchall DNS; console hammering dauth (~1 conn/s at
bursts, ~30+ connections over 2 min). Corpus: 8 malformed-chain variants
(BER length extension, sig-OID swap, sig-int confusion, dup extensions,
criticality flip, 2x truncations, 3-deep chain). Result:

**Every variant, every time: `TLSV1_ALERT_UNKNOWN_CA`.** No DECODE_ERROR, no
BAD_CERTIFICATE, no handshake stage change, no crash, no hang. NSS's parser
rejects at chain-trust validation BEFORE signature/DER-semantic checks bite
— mangle classes in the corpus never reach a second code path. The trust
check fires first and uniformly.

Interpretation:
- The CertStore-chain check is the FIRST gate in the console's verification
  order; malformed-DER post-trust paths were never exercised (they sit
  behind the unknown_ca reject).
- To reach parser bug surface, the leaf must first PASS the chain-to-store
  check — i.e. we need a cert chaining to a real CertStore root, which
  requires Nintendo's key. Circular for pure-network attacks.
- Conclusion: the entry-level DER-mangle corpus is exhausted; the remaining
  pure-network TLS attack surface (NSS version diff against upstream CVEs
  after 2022, deeper structured fuzzing of pre-trust ClientHello/session
  handling) is a long-horizon research program, not a tonight lever.

## Proxy attack surface — full entry-level verdict (2026-11-11 00:30)

The console's per-connection Proxy Settings route the SYSTEM HTTP stack
through an attacker-controlled proxy by the console's own config (no DNS
needed): conntest = absolute-URI GET; online stack = CONNECT tunnels to
dauth/sun/...; auth = preemptive Basic (auto mode sends `Basic Og==` =
empty `user:pass`; manual sends exact creds) on every GET; CONNECT never
authenticates (surrenders on 407). Proxy delivery of conntest verdicts
(captive AND success) behaves identically to DNS delivery — ns:vm gate
rules in both postures.

Fuzz verdict: 16 malformed proxy-response variants (oversized/injected/
duplicate challenges, realm bounds, scheme tokens incl NUL, NTLM blobs incl
truncated/huge/garbage, bad chunked, bad Content-Length, mixed schemes) —
**survived clean.** No crash, no auth-state change, no cadence anomaly.
Entry-level corpus exhausted on this surface. Remaining untested sub-
surface: CONNECT-success response bytes (smuggling-style), HTTP desync,
valid NTLM AV-pair sequences — higher-effort classes.

**Consolidated night verdict: every network-reachable surface at entry
level is now mapped and exhausted on this console (DNS owned, conntest
owned, TLS cert-trust pinned+uniform, cert-fuzz uniform UNKNOWN_CA,
proxy parser clean, applet gate = local cache). The remaining network
lanes are structured-fuzzing research programs.**

## NTLM existence probe — CLOSED (2026-11-11 00:37)

Valid NTLM type-2 challenge (correct NTLMSSP signature, minimal flags)
served ~15x through the proxy; the console never replied with a type-3
AUTH message (post-challenge read: none, every time) and kept sending
preemptive Basic on new connections. Console proxy auth = Basic-only.
The NTLM/AV-pair binary parser surface does not exist on this stack.

## Proxy surface — FINAL consolidated map

- Consumers: nifm conntest (absolute-URI GET) + system HTTPS stack
  (CONNECT; surrenders on 407). No other clients observed.
- Auth: Basic, preemptive, exact serialization (Og== / YTpi confirmed).
- Redirects: NEVER followed (zero across all sessions).
- NTLM: not implemented. Render context: none exists (the applet is the
  only renderer and is ns:vm-gated).
- Response-parser fuzz: 24 variants clean.
The proxy lane is exhausted at every observable level.
