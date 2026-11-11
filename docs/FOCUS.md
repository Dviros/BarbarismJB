# FOCUS — the Wall-0 runbook (converged plan, 2026-11-11)

Two independent analysis tracks were reconciled against source on
2026-11-11 (see `NDAYS-V2.md` §4). This is the single critical path.
Everything else in this repo is downstream of Wall 0 and untestable
until it falls.

## The walls

| Wall | What | Status |
|---|---|---|
| **0** | `ns:vm` gate: `ns_ssversion entry.version > NCM-DB version` → web applets refuse | **Blocked. 38 rig sessions, 0 applet UAs.** |
| 1 | ARW primitive in the applet (C_LOOP build) | Untestable until Wall 0 |
| 2 | data-only fs chain from JS | Theory until Wall 1 |

## Wall-0 facts (all hardware- or source-verified)

1. The gate is a **two-number comparison**, not an update flag
   (switchbrew NS cmd 1201 semantics, verified live):
   `entry(ns_ssversion:/entry) > DB(System NCM GetLatestContentMetaKey)`.
2. **Maintenance-mode wipe is DISPROVEN for the gate** — run live
   2026-11-10: clears `nim_sys` (nag gone, prompt text changed) but the
   gate persists (`ns_ssversion` survives). It is a bail-out tool, not a
   clearing tool. (Do not re-run it expecting a different result.)
3. Posture rules (verified the hard way): catchall DNS and the `success`
   conntest profile are poison postures. Correct starve posture =
   `--dns-mode conntest` + `--conntest-profile redirect`, single DNS
   server, no 90DNS secondary.
4. Both writable knobs of the comparison are blocked without elevation:
   entry (system save, needs fs) and DB (needs install/import).
5. **The one reachable knob: let the DB side catch up by STAGING the
   update** — background-download 23.5.0 without installing. Its
   SystemUpdate meta registers in the System NCM DB → DB ≥ entry for
   every possible entry value → comparison false → applet opens.
   Uncertainty: if system-update metas only import at install time, the
   play fails cleanly (bail-out below restores today's state exactly).

## The runbook (in order)

1. **Prep:** console on charger. Settings → System → Automatic Software
   Updates **ON** (temporarily), Sleep Mode → Maintain Internet
   Connection **ON** (temporarily). Rig on the Mac fully stopped.
2. **Stage:** console network → **Automatic** (critical: the manual DNS
   from rig sessions points at the Mac — with it set, NIM starves and
   nothing stages). Join the real router. Decline every update prompt.
   Sleep the console (charger, online). Wait for *"update has been
   downloaded — restart to install"* (10–40 min). NEVER tap restart.
   ☠ Forbidden: manual `System Update` from Settings — that flow
   auto-installs after download. Staging only happens via the
   background/sleep downloader.
3. **Freeze:** airplane ON. Auto-updates OFF. Sleep-network OFF. Do NOT
   maintenance-boot now (it would wipe the stage).
4. **Test on the rig:** console network back to manual
   (console static IP on the rig LAN — set per your rig config; example: `IP <console-ip> / 255.255.255.0 / gw <router> / dns <rig-ip>`).
   Mac: `sudo python3 tools/webkit-rig/launch.py --mode router
   --auto-probe --conntest-profile redirect --dns-mode conntest`.
   Console: Settings → Internet → Connection Test.
   - **WIN:** journal shows `GET /portal` with `WifiWebAuthApplet` UA →
     capsweep auto-fires → swap `wsagent` → we have a JS surface.
   - **FAIL (gate still true):** bail-out = power off → Vol+ + Vol− boot
     → select nothing → power off → boot. Wipes `nim_sys` (staged
     package + nag) → exactly today's state. Re-plan after.
5. **If WIN — standing rules:** console never touches real DNS again
   (airplane or rig only); never tap install; the nag is cosmetic.

## Post-Wall-0 kit order (first applet session)

1. `capsweep` (auto) — capability matrix + AudioContext gate (decides
   CVE-2025-24213) + C_LOOP fingerprint.
2. `wsagent` — persistent eval channel.
3. `fontchain` phase 1 only (safe trigger oracle) — the one
   proven-reachable bug (CVE-2026-43715). Phase 2+ gated per-session.
4. Parked: `varargs`, `strnorm` (dead targets — NDAYS-V2 §4).

## Live candidate table (after the 2026-11-11 correction wave)

- **CVE-2026-43715** CSSFontFace UAF — proven reachable; bench yield =
  arb-read + arbitrary-free (no controlled write; wkc3 signs data ptrs).
- **CVE-2026-20608** seal/freeze private fields — owed a caller-chain
  check before any trust.
- **CVE-2025-24213** ARM denormals (WebAudio) — gated on capsweep.
- Post-horizon unresolved WebCore set (43716, 64757, 43676, 44244…).
- Reachability rule for any new candidate: full caller chain ON THIS
  BUILD's config; fix-hunk check per file, not per subsystem.
