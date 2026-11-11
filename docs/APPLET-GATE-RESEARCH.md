# APPLET-GATE-RESEARCH — WifiWebAuthApplet launch gate + cached update state

Researched 2026-11-10 (live session against fw 23.0.0 console). This is the
answer to the "this feature is not available" wall.

## The gate, identified (switchbrew-documented)

The refusal is the **ns:vm / safe-system-version check**:

- **ns:vm** (`IVulnerabilityManagerInterface`, switchbrew NS services): cmd
  1200 `NeedsUpdateVulnerability` — "**Web-applets use this command to check
  if the system needs an update**." Cached safe-version lives in system
  savegame **0x8000000000000049** mounted as `ns_ssversion:/` (file
  `ns_ssversion:/entry`).
- **NIM** cmd 142 [17.0.0+] `RequestCheckSafeSystemVersion`: async network
  request with **bvc** — domain `bvc-hac-%.cdn.nintendo.net`. Switchbrew's
  verbatim warning: "**Attempting to block this domain may result in the
  applets which use ns:vm displaying error message 'This feature is not
  available' (possibly related to newer-version already being cached?)**."

Our console exactly: fw 23.0.0 with cached meta that a newer fw exists (23.0.1
shipped Oct 1) → `NeedsUpdateVulnerability` = true → the applet refuses.

## Why the bench's console worked and ours doesn't

The bench ran on **23.0.1 — the newest firmware at the time** → nothing newer
cached → gate = false → applet launched (their issue #1 confirms the full
chain ran in the applet on 23.0.1). Not a TLS difference — a CACHE difference.

## OUR TWO POSTURE MISTAKES (both fixable right now)

1. **`--dns-mode catchall` POISONS the console.** The bench **NXDOMAINs**
   everything except the ctest hosts (sun, bvc, aqua, dauth, atumn → rcode
   3). We have been *answering* those hosts (→ our IP) and letting them fail
   at TLS — that "answering-and-failing" is exactly the NIM-poisoning
   interaction switchbrew warns about. Our ORIGINAL `conntest` mode is the
   correct posture.
2. **The `success` profile (200 + X-Organization) is a documented TRAP.** The
   bench explicitly recorded that their `connectivity_ok` profile produced
   "supernag / forced online → 'this feature is not available' → 2807-1006".
   We ran it for an hour tonight.

## Clearing the cached update state WITHOUT updating (stock, documented)

**Maintenance Mode deletes `nim_sys` savedata on boot** (switchbrew NIM
Notes: nnMain "calls a savedata init function with a flag based on boot mode.
When flag is set, it deletes the savedata `nim_sys`").

Procedure (S1+S2):
1. **Airplane mode ON** first (or delete saved networks) — so NIM cannot
   re-cache the moment it boots.
2. Power off completely.
3. Hold **Vol+ + Vol−**, press **POWER**, keep both held until the
   maintenance menu appears.
4. **Select NOTHING.** Power off.
5. Boot normally, join the rig network.

S1 community-corroborated that entering alone drops the pending update. S2
parity: same NIM architecture, high confidence, community-verified via
maintenance-mode fix reports (The Verge).

## The correct rig posture (bench-exact)

```sh
python3 tools/webkit-rig/launch.py --mode router --auto-probe \
    --conntest-profile redirect --dns-mode conntest
```
- `conntest` mode: answers ONLY the three ctest hosts; NXDOMAIN for
  everything else (the starve posture).
- `redirect` profile: 302 → /portal, no X-Organization.
- Fresh conntest after maintenance boot: airplane cycle → connection test →
  registration prompt → **this time the gate should be gone** → applet
  follows the 302 → `GET /portal` (WifiWebAuthApplet UA) → telemetry →
  auto-probe fires.

## Date trick verdict

3DS-only. On Switch the cached state is NCM content-meta + `ns_ssversion` +
`nim_sys` savedata — clock-independent. (Explains tonight: banner aged, root
cause remained.)

## Nuclear option (do NOT take yet)

Update to newest fw → `NeedsUpdateVulnerability` = false (bench state) — but
23.5.0 patches the fs bug AND may desync the WebKit build. Only if the entry
is confirmed on that exact build. It is not.

## Gate-clear recipe + acquisition landscape (2026-11-11 research wave)

**Entry format (switchbrew NS cmd1201/1202 + Gag-Order dumps):**
`ns_ssversion:/entry` = u64 SystemUpdate ApplicationId + u32 version on the
**ContentMeta/CNMT scale** (not display version; 4.x-era consoles all held
`0x816`=2070). The `policy` field served by cmd1202 comes from settings, not
the file. **Gate is TRUE only when entry.version > NCM-DB latest SystemUpdate
meta** → the fix is to write an entry whose version ≤ installed 23.0.0.
S2 applets use ns:vm 3100/3101 (→ NIM cmd142 → bvc
`https://bvc-hac-%.cdn.nintendo.net/<fw-triple>`; response format undocumented).
No retail command resets the entry (3102 is debug-only).

**Write recipe (once any fs session exists — near-turnkey):** mac2jb's bundled
ns2-savekit READ path already handles system saves unpatched
(`save-pull-root.cjs --space 0 --type 0 --static-id 8000000000000049`); the
write path needs ~10 lines (write `staticSaveDataId` at attribute +0x20, use
cmd 52 `OpenSaveDataFileSystemBySystemSaveDataId`, whitelist the id). Pull the
live entry first, patch its version field down, write, Commit, **reboot
offline** (ns caches the check result; reboot is the reliable flush). A failed
bvc check does NOT poison (bench ran NXDOMAIN'd with entry==installed = open).

**Acquisition landscape (2026-11-11, all verified):** SmileBASIC 4 full+demo
delisted worldwide Oct 22–25 2026 *because of ns2jb*; **no cartridge ever
existed** (download-only since 2019). All Artemis demos pulled (Seedsow,
Nora2, Hamidashi Creative ~Nov 5; Nora HD likely). 23.5.0 shipped Nov 10
2026 (ns/nim/systemWeb/openWeb rebuilt; fs bug patched). **Only live entry =
Civ VII Switch-1 1.0.0 cart + CivSwitch** — works on 23.0.0 — but CivSwitch's
JS loader does not expose ns2jb's fs RPC: stage-B port into the Civ7 sandbox
is BarbarismJB's engine work (needs the cart for M0 offsets).

**Factory-reset lane (free, destructive):** full initialize formats SYSTEM
partition incl save 0x49 → fresh no-entry console on the starved rig should
present gate=FALSE (absent entry is not > DB). Unknown: whether the first
applet launch blocks pending a 3101 check when no entry exists (bench state
was entry==installed, not absent). Console stays 23.0.0 through reset. This
is the only no-cost, no-game path to opening the applet.

## Sources

switchbrew: NS services / NIM services / Network / Internet Browser / libnx
web.h · Jmesmykil repo (ON-DEVICE-MARKERS.md, observed-entry.py, issue #1) ·
Nintendo 42967/2811-1006/2807-2806 · GBAtemp 649030/644762/502443/416262 ·
The Verge (S2 maintenance mode) · r/switch2hacks 1xfs3yr et al.
