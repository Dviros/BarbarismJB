# BarbarismJB research roadmap — kernel, keys, persistence, content loading

Where we stand after L4 (arbitrary sysmodule code exec, fs compromise,
cross-process patching) and what each next goal realistically requires.
Grounded in the validated facts in docs/STATIC-VALIDATION.md; rumor-free.

## The privilege ladder (what blocks what)

```
L4  sysmodule exec + process patching      ← WE ARE HERE (post-M4)
L5  derived-key recovery (spl/es oracles)  ← research program, see K1
L6  TrustZone / secure monitor             ← no known path (K2 stretch)
L7  kernel (EL1)                           ← no known path (K2)
L8  boot chain / signed content            ← requires L6+L7
```

Everything below L5 is gated by L6/L7. There is no public Switch 2 kernel
exploit, no TZ compromise, and no keys as of 2026-11-10. What changed with
ns2jb-class access is that the *research tooling* for L5-L7 can now run in
place, at privilege, on stock hardware.

## K0 — build the research platform (now, on our current chain)

Everything here is buildable the day M4 passes on hardware:

1. **On-console svc monitor.** The RO payload already executes with a broad
   svc set (0x73-0x78 verified in the NPDM). Extend it with a syscall
   tracing/fuzzing harness: replay malformed svc invocations from a
   sysmodule context, journal results, survive crashes (tethered anyway).
   Historically (Switch 1) this class of access is what made kernel bugs
   findable at all.
2. **Sysmodule instrumentation.** We can patch any ordinary sysmodule's code
   in place (0x524F0014). Use it to hook `fs`, `es`, `spl`, `ns` at their
   IPC entry points — a live protocol tracer on stock 23.0.1.
3. **Encrypted boot-chain capture.** At L2 (BIS access) read the BOOT
   partitions: encrypted package1/package2 per boot. Useless for static RE
   until keys (K1) — but version/structure diffing of package1 across
   firmwares is possible encrypted, and we already own the reference
   archive for the system-program layer.
4. **Kernel static RE is BLOCKED on purpose to note it:** package2's kernel
   section is AES-CTR encrypted with a TZ-only key; the CodeFS dumper
   (yours and ours) cannot see built-ins. No dump = no disasm = dynamic
   black-box analysis (K0.1) is the only kernel surface we can touch today.

## K1 — keys: the spl/es oracle program (research, high value)

Two facts from our own static validation make this concrete:

- **ro's SAC includes `spl:`** — our payload process is an *authorized
  secure-monitor crypto client* on stock firmware. `spl` brokers crypto
  OPERATIONS (encrypt/decrypt/derive with internal keys), not raw keys —
  by design. But operations are oracles:
  known-plaintext/ciphertext techniques against derivation chains were
  historically how large parts of Switch 1's key material fell once an
  attacker controlled an spl client. No public recipe exists for Switch 2 —
  this is a genuine research program our chain unlocks.
- **`es` is an ordinary sysmodule — patchable at L4.** Switch 1's Lockpick
  recovered titlekeys by *corrupting es from userland*; we can patch es
  code directly and read its key material in memory. The Switch 2 analog
  is unproven but the position is strictly stronger than anything public.

Realistic targets: titlekeys, per-console derived keys, content-permission
keys reachable via services. NOT realistic without L6: master keys,
package1/package2 keys, keyblobs (TZ-resident).

## K2 — kernel (the open problem)

No known path. Candidate surfaces, in order of tractability:

1. **svc handler bugs** found with the K0.1 fuzzer from a privileged
   process. Expect hardening: T239 PAC, BTI, likely shadow-stack-era
   mitigations in kernel code. Long grind, but it is THE classic path and
   we can start it on hardware.
2. **Patch `spl` to reach `svcCallSecureMonitor` with attacker-chosen
   arguments** (spl is the broker that legitimately talks to the monitor).
   Arbitrary SMC = the historical gateway to TZ research. Unknown what the
   Switch 2 monitor validates; expect lockout, but nobody has publicly
   probed from this position.
3. **Package2 static RE** becomes possible only after K1 yields its key or
   K2 yields TZ read.

Honest odds: unknown, months-to-years of effort, may require multiple bugs
chained. This is why nobody has it.

## P — persistence ladder

| Tier | What | Status |
|---|---|---|
| P0 | XSTRIG save trigger (menu → Load Game) | HAVE (CivSwitch installer) |
| P0.5 | Sleep/wake keeps the elevated session (processes survive sleep) | LIKELY — verify on hardware first session |
| P1 | Zero-navigation auto-trigger at boot (main-menu save card rendering the XSS string) | cheap experiment: check whether the main menu's "continue" card renders `currentTurnDate` like the save list does; if yes, installer writes a second stager there |
| P2 | True boot persistence (custom sysmodule in NAND) | requires signed content ⇒ L8 ⇒ blocked on K1/K2. **Deliberately out of scope; BIS SYSTEM writes are a brick vector.** |

## G — content loading

- **Modded builds of games you own** — AVAILABLE in principle today: the
  chain's ExeFS domain-swap (ro/files.cjs) mounts attacker `main` under a
  chosen program ID; pepsipu's modded Mario Kart World demo is exactly
  this. Generalizing the donor from ro's program ID to an arbitrary
  installed title's ID (+ that title's genuine NPDM, same pattern) is a
  contained piece of work after M4: the "Barbarism loader". Per-boot,
  in-memory, no install, own content only.
- **Loading content you don't own** — requires defeating content
  signatures = L8 = same research wall as P2, and outside this project's
  scope (research on owned hardware, matching upstream ns2jb's explicit
  "not a piracy tool" stance).

## W — the WebKit host provider (free, game-free entry)

Status after the 2026-11-10 workstream (docs/WEBKIT-ANALYSIS.md,
WEBKIT-ENTRY.md, WEBKIT-EXPLOIT-RESEARCH.md, WEBKIT-NDAYS.md,
WEBKIT-BACKPORT-CHECK.md, docs/RIG.md, tools/webkit-rig/, tools/jsc_options.py):

| Step | Status |
|---|---|
| W1 entry vector | ✅ confirmed: DNS-hijacked plain-HTTP conntest → 302 → WifiWebAuthApplet (no whitelist, **no TLS, no pinning to break**) |
| W2 local rig | ✅ built + self-tested (tools/webkit-rig: dns.py 13/13, portal.py 27/27, probe page 12/12) — hardware run pending |
| W3 engine ground truth | ✅ from the reference dump: WebKitGTK-2.39.1-era fork (WKC 3.12.11), B-key PAC frames, no BTI, JIT fully compiled in |
| W4 JIT verdict | ✅ **JIT ON, no cage** (useJITCage=0, all tiers default 1, decoded from Options::initialize); exec pages via svc 0x2C; pool RWX-vs-dualmap = one rig probe |
| W5 ARW n-day | ⚠️ narrowed to **CVE-2023-32439** (static check INCONCLUSIVE — compiler erased the fingerprint); Enki bug backported-FIXED; runtime miscompile probe on the rig is the gate |
| W6 ARW→exec | two viable paths, both avoid PAC forgery: (a) JIT-page write via wkcMemory*Peer; (b) **no exec at all** — data-only IPC forging of the applet's own fsp-srv requests (pepsipu's stated direction) |
| W7 chain port | civshim-webkit + offsets/webkit-23.0.1.json (applet modules); fs-side engine unchanged |

Sequencing within W: W2 hardware run (prove entry + telemetry) → W5 runtime
probe (32439 miscompile test; Enki as negative control) → W4 pool probe →
exploit port → W6 → W7.

## Sequencing recommendation

1. Hardware M0-M4 (the chain itself) — everything above rests on it.
1b. **WebKit W2 rig run in the same session** (minutes: a Wi-Fi AP or router
   DNS override + `python3 tools/webkit-rig/portal.py`; success = telemetry
   line with the WifiWebAuthApplet UA) — plus the W5 32439 probe.
2. P0.5 + P1 verification (one session, cheap, big usability win).
3. K0 platform (svc monitor, es/spl hooks) — turns the console into a
   research rig.
4. K1 spl/es oracle program — best effort-to-value on the board.
5. K2 only with K1 results in hand.
