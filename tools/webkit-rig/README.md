# BarbarismJB webkit-rig — operator runbook

Local test rig that puts our own JavaScript into the Switch 2's
WifiWebAuthApplet over the captive-portal vector, on stock firmware
23.0.1, with zero exploits. It proves the entry surface, collects
telemetry, and serves the applet strike kit (capability census, WS eval
agent, phased exploit-oracle harnesses) via deliberate per-page swaps.
Nothing here is a code-execution payload (that is a separate workstream —
see `docs/RIG.md` and `docs/WEBKIT-EXPLOIT-RESEARCH.md`).

Mechanism in one paragraph (`docs/WEBKIT-ENTRY.md` §1, §5): the console's
connectivity test polls plain-HTTP hosts (`ctest.cdn.nintendo.net`,
`ctest.p01.ctest.srv.nintendo.net`, `conntest.nintendowifi.net`). We answer
those names on the LAN with our bench IP; our HTTP server replies WITHOUT
the `X-Organization: Nintendo` header — that missing header IS the
captive-portal trigger — and 302-redirects to `/portal`. The system opens
the WifiWebAuthApplet (a NetFront/WKC WebKit applet with no URL whitelist,
plain HTTP by design), which follows the redirect and runs the probe page.
No TLS, no pinning to break.

**Scope: your own hardware, your own LAN. Never expose any of this to the
WAN.**

## Files

| file | role |
|---|---|
| `launch.py` | one-command macOS orchestrator: preflight (incl. stale-rig-listener hygiene), pf anchor, services, telemetry watcher, session journal |
| `dns.py` | authoritative LAN DNS (UDP+TCP): answers the conntest hosts with our IP, NXDOMAINs the rest (or catch-all) |
| `portal.py` | HTTP server: conntest → 302 without `X-Organization`; `/portal` current page; `/page/<name>` direct serving; `/report` telemetry sink; `/stage/*` payload staging; `/ws` WebSocket bridge; local-only `/rig/swap[?name=]`, `/rig/phase`, `/rig/ws/send`, `/rig/ws/state` |
| `portal.html` | the schema-1 page that runs inside the applet (environment/features/JIT/WS telemetry) |
| `pages/` | applet strike kit, auto-registered by filename stem: `capsweep.html` (capability census), `wsagent.html` (WS eval-RPC agent), `fontchain.html` (phased CSSFontFace UAF harness) |
| `pages/parked/` | PARKED-DEAD oracle pages kept for archaeology (`varargs.html`, `strnorm.html`) — never registered, never swappable; see docs/NDAYS-V2.md §1/§4 |
| `probe-32439.html` | RETIRED from the auto-chain (CVE-2023-32439 is FTL-only, this console has no JIT). Kept as a manual inverted no-JIT falsifier: serve with `--probe-page probe-32439.html` + `/rig/swap`; a `jit_tiering_likely` stage-A verdict would falsify the no-JIT model — its stage-B variant verdicts are meaningless here |
| `runs/` | telemetry output + `rig-sessions/` journals — created at runtime |
| `stage/` | drop files here to serve them at `/stage/<name>` — created at runtime |

Requirements: macOS host (primary), Python 3.8+ (stdlib only). macOS 27
verified; see `docs/PORTING.md` for the future Windows/Linux surfaces.

## Quickstart (macOS) — one command

```sh
python3 -m py_compile tools/webkit-rig/launch.py tools/webkit-rig/portal.py tools/webkit-rig/dns.py
python3 tools/webkit-rig/launch.py --self-test     # expects: PASS (0 failures)
python3 tools/webkit-rig/launch.py                 # router mode, interactive
python3 tools/webkit-rig/launch.py --mode list     # interfaces + Internet Sharing state
```

Serve a strike-kit page to the applet once the rig is up (deliberate,
local-only; nothing swaps automatically anymore):

```sh
curl -X POST 'http://127.0.0.1:8080/rig/swap?name=capsweep'    # next /portal load runs it
curl -X POST 'http://127.0.0.1:8080/rig/swap?name=portal'      # back to the schema-1 page
```

`launch.py --mode router` (the default):

1. **Preflight** — enumerates IPv4 interfaces (`networksetup` + `ifconfig`),
   picks the LAN interface (interactively if several; `--interface en0` /
   `--ip` to pin), REAPS stale webkit-rig listeners from prior sessions on
   80/443/53/8080/5353 (only processes whose command line is ours — foreign
   listeners are reported and never touched), checks the high ports, reads
   Internet Sharing state (read-only) and warns about pf.
2. **Privileges, done right** — portal.py and dns.py run UNPRIVILEGED on
   8080/5353; a minimal pf anchor `com.barbarismjb.rig` (table-less rdr on
   the chosen interface only) redirects tcp 80→8080 and udp+tcp 53→5353.
   Loaded with `sudo pfctl -a com.barbarismjb.rig -f -`; teardown removes
   ONLY that anchor. Your global pf state (`/etc/pf.conf`, pf on/off) is
   never touched. macOS reality check: the anchor is only *evaluated* if
   the main ruleset references it — stock `/etc/pf.conf` references only
   `com.apple/*` — so the launcher verifies this live (read-only sudo) and
   falls back to direct privileged binding (one explained sudo prompt,
   services on 80/53 dropping privileges after bind), then to high-port
   mode with instructions. Add the one-time
   `rdr-anchor "com.barbarismjb.rig"` line to `/etc/pf.conf` if you want
   the anchor path permanently live (operator-owned edit; the launcher
   refuses to do it for you).
3. **Console steps** — printed with the detected IP, including the
   DO-NOT-UPDATE warning (keep the console on 23.0.1; never
   test-update while rigged).
4. **Telemetry hooks** — the runs file is tailed live; the first
   WifiWebAuthApplet UA prints a banner, and every strike-kit page report
   (`data.page` marker) journals a `page_report` event with a headline.
   Which page the applet gets is the operator's explicit `/rig/swap` —
   nothing auto-swaps (the old `--auto-probe` chain is retired; the
   32439 detector was FTL-only and this console has no JIT).
5. **Session journal** — `runs/rig-sessions/<ts>/`: `config.json`,
   `events.jsonl`, `portal.log`, `dns.log`, `telemetry/` (the runs file
   itself), `exit-summary.json`. Everything needed to file a bug on
   ourselves.
6. **Ctrl-C (or SIGTERM)** tears down: services stopped, anchor flushed,
   port release VERIFIED (retry loop warns and journals if something
   still holds 80/443/53 — the next session's hygiene pass will reap it),
   summary written, console-cleanup steps printed.

`launch.py --mode standalone` (EXPERIMENTAL): guides through System
Settings → General → Sharing → Internet Sharing. Two honest caveats are
printed up front: the shared SSID derives from the Mac's name, and macOS's
sharing DNS proxy conflicts with our dns.py — the console MUST use manual
DNS to the detected bridge IP (detection is authoritative; default
192.168.2.x, renumbers on collision). Enable sharing, then re-run the
launcher.

## Console ritual

1. Settings → Internet → select the network → **Connect to This Network**
   (or run the connection test on an already-saved network).
2. The test "fails" — that is the captive-portal detection working — and
   the portal applet opens on our probe page. Press **+ (Information)** to
   confirm the loaded URL (`http://<bench>/portal`).
3. Watch the page's status card turn **TELEMETRY SENT**, then keep it open
   until the launcher prints the applet banner. Kit pages you swapped in
   journal their reports as they run.

## What success looks like

- The launcher prints the ENTRY SURFACE LIVE banner (first
  WifiWebAuthApplet telemetry).
- A `runs/…/telemetry/rig-*.jsonl` line exists with `ua` containing
  `WifiWebAuthApplet` and `AppleWebKit/` — the primary evidence the entry
  surface is live on your firmware.
- Swapped kit pages produce `data.page` lines (`capsweep` full census,
  `wsagent` connect/heartbeat status, `fontchain` phased verdicts) and
  `page_report` events in the session journal.
- `exit-summary.json` in the session journal tracks per-console-IP
  first-seen state and teardown results (including the port-release
  verification).

## Advanced — manual paths (no launch.py)

Kept for bench hosts where you want each piece in its own terminal.

**Path A — dedicated bench AP (fully offline).** A Linux host (laptop/Pi)
with a Wi-Fi card is the AP; the Switch 2 joins this SSID only. hostapd +
dnsmasq (DHCP option 6 = bench IP as DNS); full configs in
`docs/PORTING.md` §Linux — the same shape works as macOS's future
replacement. Then `sudo python3 tools/webkit-rig/portal.py --ip
192.168.70.10` (dns.py optional when dnsmasq answers the conntest set).

**Path B — existing home LAN + manual DNS.**

```sh
sudo python3 tools/webkit-rig/dns.py --ip <bench-lan-ip>            # must be :53
sudo python3 tools/webkit-rig/portal.py --ip <bench-lan-ip>         # must be :80
python3 tools/webkit-rig/portal.py --ip <bench-lan-ip> --port 8080  # high-port lab variant
# manual 32439 inverted no-JIT falsifier (retired from the auto-chain):
python3 tools/webkit-rig/portal.py --ip <bench-lan-ip> --port 8080 --probe-page tools/webkit-rig/probe-32439.html
curl -X POST 'http://127.0.0.1:8080/rig/swap'   # then serve it at /portal
```

Console: DNS Settings → Manual → Primary DNS = `<bench-lan-ip>`. Both
scripts drop back to your uid after binding. Verify the legs:

```sh
dig @<bench-lan-ip> ctest.cdn.nintendo.net A     # -> bench IP
dig @<bench-lan-ip> nintendo.com A               # -> NXDOMAIN (default mode)
curl -H 'Host: ctest.cdn.nintendo.net' http://<bench-lan-ip>/   # -> 302 to /portal
```

## Cleanup (after every session)

1. Tell the console it is online: run portal.py in success mode briefly —
   `sudo python3 tools/webkit-rig/portal.py --ip <ip> --conntest-mode
   success` — then re-run the console connection test (it sees
   `X-Organization: Nintendo`, clears portal state, reports success).
   Stop the server afterwards.
2. Console: DNS Settings back to **Automatic**.
3. Path A: forget the bench SSID; stop hostapd/dnsmasq.
4. launch.py already flushed its pf anchor (if it loaded one); if you ran
   the manual paths, there is nothing pf-related to undo.
5. Keep the bench console on 23.0.1 and never join a real network with it
   while any modified state (manual DNS) is set.

## Troubleshooting

| symptom | fix |
|---|---|
| launcher says W_PF_UNREFERENCED | stock macOS only references `com.apple/*` anchors; add the one-time `rdr-anchor "com.barbarismjb.rig"` line to /etc/pf.conf and reload, or accept the direct-bind fallback (sudo on 80/53), or use `--bind-mode direct` to skip pf entirely. |
| launcher says W_PF_DISABLED | pf is off system-wide; the anchor is inert until enabled. The launcher never enables pf (global state). |
| portal does not open | re-run the connection test; toggle airplane mode; delete and re-add the network. Confirm DNS actually points at the bench (`dig @<bench> ctest.cdn.nintendo.net`) and the HTTP leg answers (`curl -H 'Host: ctest.cdn.nintendo.net' http://<bench>/` must return the 302). |
| console "remembers" a portal | cached portal state: run the success-mode server (cleanup step 1) once, re-test, then go back to portal mode. |
| DNS leg dead | dns.py not reachable on :53 — check sudo/redirect, check the console's DNS screen really shows the bench IP. |
| HTTP leg dead | port 80 already in use (`lsof -nP -iTCP:80 -sTCP:LISTEN`) — stop the other service, or let launch.py's redirect/fallback handle it. |
| page loads but no telemetry | check `/portal` really rendered the probe (Information button); the page retries with backoff for ~16 s — watch the access log for `/report` POSTs. |
| 32439 page (manual falsifier) | stage-A `jit_tiering_likely` would FALSIFY the no-JIT model — re-check the engine config before anything else. Stage-B variant verdicts are meaningless on this no-JIT console (the miscompile lives in FTL); the page is otherwise retired. |
| port 80/443/53/8080/5353 busy at startup | launch.py's hygiene pass reaps STALE webkit-rig listeners automatically and logs each; a NON-rig holder is reported (pid + command) and never touched — free it yourself or change ports. |

## Safety notes

- **LAN-only.** Everything binds the chosen LAN interface IP — do not bind
  `0.0.0.0` on a WAN-attached host, do not port-forward 53/80 to the
  bench, do not run this on public Wi-Fi.
- **The rig IS the console's DNS while testing.** It never forwards
  upstream: the console cannot resolve Nintendo update/telemetry endpoints
  for the duration — intended isolation, equivalent in effect to 90DNS.
- Plain HTTP everywhere, by design; there is no TLS to configure and none
  to intercept.
- Everything the console sends lands in `runs/` and session journals on
  the bench host only.
- This bench exists to test our own console on our own network using the
  captive-portal applet exactly as Nintendo built it to be used. Do not
  system-update the console while rigged.
