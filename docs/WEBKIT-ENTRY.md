# WebKit entry for BarbarismJB — delivery mechanism, TLS posture, test rig

Research date: 2026-11-10. Web-sourced; every claim tagged **[verified]** (primary
source or multiple independent corroborations), **[reported]** (single-source
secondary, e.g. Discord messages relayed by press), or **[unverified]**.
Companion docs: `ROADMAP-KERNEL.md`, `HOMEBREW.md`.

**Headline:** the Switch 2 has no user-facing browser, but its WifiWebAuth
captive-portal applet still loads plain-HTTP attacker content after a LAN DNS
hijack of Nintendo's connectivity-check hosts — and that is exactly how
pepsipu's WebKit entry is reached. **No TLS, no pinning break is required:
the vector is HTTP by design.** A public third-party research bench already
replicates the flow on a local network end-to-end.

---

## 1. How WebKit is reached on Switch 2 without a game

### 1.1 The captive-portal path — Switch 1 lineage (documented baseline)

SwitchBrew is the authoritative reverse-engineering record
([Internet Browser](https://switchbrew.org/wiki/Internet_Browser),
[Network](https://switchbrew.org/wiki/Network)) **[verified]**:

- The console runs a **connection test** against a connectivity URL. Old host:
  `http://conntest.nintendowifi.net/`; later replaced by
  `ctest.cdn.nintendo.net` (per the Network page). A third form seen in
  2026-era tooling: `ctest.p01.ctest.srv.nintendo.net`.
- **The conntest is plain HTTP.** Captive detection is header-based: a
  captive portal is flagged when the response **lacks the header
  `X-Organization: Nintendo`**. No TLS is involved in the trigger.
- On detection, the system launches **WifiWebAuthApplet** (AppletId 0x19,
  ShimKind 6 "Wifi", available since fw 2.0.0) — a NetFront/WebKit browser
  applet. Its **initial page is the conntest URL itself**; the
  `WebWifiPageArg` struct carries a 0x100-byte conntest URL (polled with SDK
  libcurl to decide connectivity) plus a 0x400-byte initial URL that is then
  navigated. In other words: the applet re-requests the attacker-controlled
  URL and renders whatever comes back, following redirects.
- **WifiWebAuthApplet has no URL whitelist** ("Uses whitelist: No" — the
  whitelist files of other applets literally do not exist in it). Later
  firmwares add `Upgrade-Insecure-Requests: 1` on plain-HTTP requests, but
  plain-HTTP content and redirects to plain-HTTP URLs remain allowed
  ("at least on S1" per SwitchBrew).
- PegaSwitch operationalized exactly this in 2017
  ([reswitched/pegaswitch](https://github.com/reswitched/pegaswitch),
  **[verified]** README): Node DNS server on port 53 + web server (80/8100);
  point the Switch's DNS at the PC, run a connection test from System
  Settings (or enter the update page) → the captive portal opens → the
  browser exploit (ROP) runs. On fw 1.0.0 the captive portal was not
  exploitable, so a JPN Puyo Puyo Tetris cart was used to launch a web
  applet instead (`--webapplet`); the later **"Fake News"** entrypoint
  ([noahc3/PegaScape](https://github.com/noahc3/PegaScape),
  [GBAtemp PegaScape DNS thread](https://gbatemp.net/threads/new-public-pegascape-dns-replacement-for-the-public-eol-dns-by-noahc3.656145))
  planted a crafted **news item** whose embedded web content loaded the
  exploit page — the news-applet precedent (see §1.3).

### 1.2 The same flow exists on Switch 2 — evidence

Ranked, strongest first:

1. **pepsipu's own blog (primary source)** **[verified]** —
   <https://pepsipu.com/blog/2026-10-switch2-jailbreak-ns2jb>, Oct 21 2026:
   *"Codex picked the browser engine, WebKit, **accessible via custom WiFi
   captive portal**."* The AI "WebKit agent" occupied his Switch 2 for the
   research loop. This is the definitive statement of *how the entry is
   reached* — a custom (attacker-operated) captive portal.
2. **A public third-party Switch 2 captive-portal research bench**
   **[verified]** —
   [Jmesmykil/switch2-captive-portal-research](https://github.com/Jmesmykil/switch2-captive-portal-research)
   ("Local captive portal and browser research bench for reproducible
   Switch 2 observations", 44 stars). Its `switch2-local-browser-entry.py`
   is a self-contained DNS+HTTP helper that:
   - answers (A records, UDP+TCP :53) only `ctest.cdn.nintendo.net`,
     `ctest.p01.ctest.srv.nintendo.net`, `conntest.nintendowifi.net`, and
     `*.savanna.srv.nintendo.net` / `*.idobata.srv.nintendo.net`, NXDOMAINing
     everything else;
   - serves HTTP :80 where any of those hosts at `/` returns a **302 to
     `http://<bench-ip>:8765/`** (the probe page);
   - the console's DNS is set manually to the bench, restored afterwards.
   The bench's observed on-device user agent is
   **`WifiWebAuthApplet … AppleWebKit/613.0`** — i.e. on Switch 2 the
   hijacked conntest still opens the WifiWebAuth applet, it follows the 302
   to an arbitrary LAN `http://` URL, and attacker JavaScript runs (the
   repo ships probe pages with `@font-face`, JSC probes, WebSocket tests,
   RPC/relay pages). This is the entire delivery mechanism, publicly
   demonstrated, offline/LAN.
3. **Community reports, June 2025 (pre-ns2jb)** **[verified via multiple
   secondary]** — r/switch2hacks "[WIP]"
   (<https://www.reddit.com/r/switch2hacks/comments/1l8yx9k/wip/>, Jun 11
   2025): after forcing DNS redirection to a custom captive portal on
   Switch 2, the poster served JavaScript and got **full `eval` access in
   the embedded browser** — the vector predates ns2jb by ~16 months.
4. **GBAtemp ns2jb thread 685698** **[verified]** (posts after page 26):
   - shaunj66 (Oct 25, p.29): the hidden browser is "necessary to connect
     to a WiFi network captive portal… an exploit could work by mimicking a
     captive portal and running the exploit via webkit."
   - flopsy (Oct 25, p.29): "You can get to a browser through setting DNS
     and let the connection fail"; also notes the third-party **switchbru**
     DNS portal service still functions on 23.0.1 (now requiring
     registration) — third-party proof the portal applet renders external
     DNS-redirected content on current firmware.
   - Ettino #517 / TheDonmatic #518 (Oct 24, p.26): "pepsipu is porting the
     Switch 2 userspace exploit to WebKit" / "There's a webkit now, no game
     is needed anymore" (linking OneJailbreak).
   - SonyUSA #602 (Oct 28, p.31): the browser exists on both Switch 1 and
     Switch 2, reachable via "WiFi login, the Health and Safety manual, and
     a few other ways" — redirecting it "works kinda janky."
5. **Switch 2 browser stack is alive in current firmware** **[verified]** —
   SwitchBrew Internet_Browser: S2 UA at 20.1.0 =
   `AppleWebKit/613.0 … NF/7.0.3.8.11 … NintendoBrowser/5.2.0.35483`
   (vs S1 613.0/6.0.3.x/5.1.0.x — same engine generation, newer NetFront
   shell). BrowserDll changes are documented through 21.0.0+
   (`core_0` → `cfi_nncfi`, core_3 removed, UrlBlackList moved to a
   SystemData). No UA change is documented for 21.0.0–23.0.1, consistent
   with the bench still seeing 613.0-era UA on 2026 firmware.
6. **Public-Wi-Fi anecdotes** **[verified as behavior, single-network
   scope]** — NintendoSoup (Jun 17, 2025): on a captive-portal network the
   Switch 2 *attempts* to load the login page (shows its URL via the "+"
   Information button); in that report the page itself 404'd on that
   particular network. Confirms the portal flow exists on S2 retail units
   in the field (independent of any exploit).

**NintendoSoup caveat reconciled:** the 404 was that network's portal
misbehaving, not S2 lacking the applet — items 1–5 above are direct evidence
the applet loads whatever the hijacked conntest serves.

### 1.3 Alternate WebKit triggers (and why they rank below the portal)

| Flow | Switch 1 precedent | Switch 2 status | Attacker-controllable? |
|---|---|---|---|
| **News applet webjump** | "Fake News" entry (crafted news item → WebApplet), PegaScape public DNS era | News became a **dedicated applet on S2** ([SwitchBrew News Applet](https://switchbrew.org/wiki/News_Applet)); news videos play in WebApplet (LibAppletWeb 010000000000100A); "doesn't seem to use a WebApplet whitelist loaded from any RomFS"; the S2 jump list `listOpenWebJump.txt` (in the 21.0.0+ UrlBlackList SystemData) = old `listLnsGlobal.txt` minus `nintendo*` | **No, not from LAN.** News content arrives from Nintendo's signed news infrastructure over HTTPS (bugyo domain); injecting a crafted item requires compromising that pipeline (or the S1-era trick of an offline news DB manipulation, not shown on S2). Rank: below portal. |
| **Account-link / Login applet** | Login applet, whitelist `WhitelistLns.txt`, invalid cert → error code | Same whitelist lineage → `listOpenWebJump.txt` on S2 | **No.** Whitelisted https URLs only. |
| **Parental controls / S2 "OpenWeb" applet** | — | New **[S2] OpenWeb applet** documented on SwitchBrew (own NPDM: acc:u1, pctl, ns:web, banana, bsd:a…); the jump whitelist above appears to be its URL gate | **No** (whitelist-governed; account/parental web flows). Listed for completeness — nothing public suggests it is reachable with attacker URLs. |
| **eShop (ShopN) embedded web** | WhitelistEc.txt | `listSystemWeb.txt` (= old `listEcGlobal.txt`) on S2 | **No.** |
| **Manual/Health & Safety** | SonyUSA's GBAtemp remark ("the Health and Safety manual") | Not documented on SwitchBrew as a web applet on S2 **[unverified]** | Unknown; "works kinda janky" per the same post. |

**Bottom line (1.3):** every non-portal web surface on Switch (and, per
SwitchBrew diffs, on Switch 2) is whitelist- and/or https-gated. The portal
applet is the one WebKit surface that by design loads *arbitrary plain-HTTP
content the network tells it to* — it exists to render unknown hotel/cafe
portals. That asymmetry is the whole attack.

### 1.4 How pepsipu's WebKit entry is actually triggered

- Trigger mechanism: **custom WiFi captive portal** — his words, §1.2(1)
  **[verified]**. No public tutorial of *his* tooling exists (his GitLab
  `pepsipu/ns2jb` has 3 commits, created Oct 21 2026, no WebKit code
  **[verified]**), but the delivery mechanism is fully reconstructable from
  §1.2(2) — an identical bench exists publicly.
- The r/switch2hacks tutorial thread `1xg2lqn` ("Nintendo Switch 2 NS2JB
  Jailbreak Tutorial") is Reddit-login-walled and not directly retrievable;
  mirrors/summaries of the sibling announcement thread `1xeg1mt`
  (~1.9k upvotes, 391 comments) describe the operational advice: go
  offline, delete saved WiFi networks, use the captive-portal vector to
  reach the exploit page **[reported — search-snippet level]**. A Facebook
  video tutorial ("Access Web Browser on Nintendo Switch 2") walks the
  Primary-DNS route to the browser **[reported]**.
- **No evidence of any game, cart, or eShop title being needed** for the
  WebKit entry; that is the port's entire point (Nintendo delisted
  SmileBASIC 4, so the WebKit path cannot be killed by store pulls).

---

## 2. SSL/TLS posture per flow — the pinning verdict

| Flow | Scheme actually loaded | Cert validation / pinning | Verdict for us |
|---|---|---|---|
| **Captive portal (WifiWebAuthApplet) via hijacked conntest** | **Plain HTTP by design.** The conntest request is `http://`; portal detection is a *missing header*, not a TLS event; applet then navigates/redirects within `http://` (verified live on S2 by the bench, §1.2(2)) | Moot for the trigger. S1 behavior for *https* pages in this applet: invalid-cert **dialog with an "ignore" option** (unique among applets) — S2 equivalent undocumented **[unverified]** | **TLS bypassed entirely. "Breaking SSL pinning" is NOT required.** Serve everything over `http://` and never leave it. |
| News applet video/webjumps | HTTPS (bugyo domain) | Invalid certs: load hangs, no bypass (S1 documented; no S2 counter-evidence) | Would need valid-TLS MitM or infra compromise → dead end for LAN research. |
| Login / Share / Lobby / OpenWeb / ShopN | HTTPS + URL whitelists (`listOpenWebJump.txt`, `listSystemWeb.txt` on S2 21.0.0+) | Error codes on invalid certs | Dead end. |
| ssl sysmodule at large | HTTPS for system traffic | **HackerOne #3174987** "Man-in-the-middle through broken SSL certificate verification" — logic flaw in the SSL sysmodule allowing forged server certs to applications; ~$20k payout reported **[unverified specifics — report page is login-walled; existence + title surfaced via search]** | Historical curiosity: even system TLS had a validation logic bug recently. Irrelevant to our portal path; do not build on it (likely fixed). |

**Pinning answer, precisely:** there is no evidence of *certificate pinning*
in any Switch browser applet (S1 docs describe trust-store validation with
per-applet error UX, not pinning). For the portal flow the question is empty
— the content is plain HTTP because captive portals cannot assume TLS. The
only TLS-adjacent hardening observed: `Upgrade-Insecure-Requests: 1` header
on plain-HTTP loads (server-side hint only; plain HTTP still loads — "at
least on S1" per SwitchBrew, and the S2 bench's 302-to-http flow proves it
holds on S2 in practice).

---

## 3. pepsipu's WebKit port — status, firmware, primitives

Timeline (all dates 2026):

| Date | Event | Source / tag |
|---|---|---|
| Oct 21 | Blog post: Codex-driven WebKit agent runs on his Switch 2 via custom captive portal. Codex *claims* ARW + "native control-flow hijack", but the realized primitive was only **calling existing native JS functions** (e.g. `Math.expm1`) — not arbitrary calls. Why it stalled: **XOM** (execute-only memory → can't read gadgets), **PAC** (can't forge signed pointers), **CFI** (type-checked call sites). Footnote: the agent "did not succeed." Future work named: *"Porting the fs sysmodule exploit to WebKit"* — trigger the known fs bug through WebKit's own filesystem code paths so arbitrary IPC is unnecessary | [pepsipu blog](https://pepsipu.com/blog/2026-10-switch2-jailbreak-ns2jb) **[verified]** |
| Oct 24 | Discord messages: exploit ported to WebKit, **works on his console on 23.0.1**, seeking testers on older firmware; relayed by OneJailbreak ("Portage du Jailbreak Switch 2 sur WebKit par pepsipu"), hit GBAtemp same day (Ettino #517) | [mezha.net](https://mezha.net/eng/news/mezha-fb9fd5317d773c1ee58dfb59_nintendo_switch_2), [NotebookCheck](https://www.notebookcheck.net/Nintendo-Switch-2-jailbreak-reportedly-works-without-additional-software.1436141.0.html), [GBAtemp 685698 p.26](https://gbatemp.net/threads/switch-2-jailbreak-ns2jb-released-software-only-exploit-tethered.685698/page-26) **[reported]** |
| Oct 28 | Press: no release date, not a full jailbreak, tethered, must re-run per boot | NotebookCheck / mezha **[reported]** |
| Early Nov | **Put on hold**: OneJailbreak "Switch 2 WebKit Jailbreak Port Put on Hold with No Release Date" ("frozen until further notice"); r/switch2hacks `1xiha6i` "BAD NEWS — Pepsipu becomes unable to release web kit… **the servers that testers used are now down too**, the community is working on recreating his hack"; r/onejailbreak `1xizqxu` (Seedsow Lullaby demo entry thread) comment: "pepsipu said the WebKit is on hold for now" | **[reported]** (multiple independent threads/aggregators) |
| As of 2026-11-10 | **Not released.** GitLab repo has no WebKit code. No public exploit primitives, no reliability data (testers' infrastructure gone). The specific rumor that the hold is *in favor of an Artemis (demo-save) entry* is **[unverified]** — what is corroborated is only: (a) on hold, (b) Artemis-class demo-save entry points (Seedsow Lullaby etc., see `HOMEBREW.md` §1.4 mac2jb) emerged in the same window as alternate no-purchase entries | GitLab **[verified]**; hold **[reported]**; Artemis causality **[unverified]** |

Public primitives inventory: none for pepsipu's WebKit chain. The only
public Switch 2 browser bug with mechanics documented is the third-party
bench's **OpenType GPOS out-of-bounds read** in the SystemWeb wrapper/parser
(flat offset `0xbac40`), explicitly "no code execution, no heap grooming",
blocked behind the same PAC/CFI/XOM wall
([repo README](https://github.com/Jmesmykil/switch2-captive-portal-research))
**[verified]**. Engine version context: S2 ships an AppleWebKit **613.0**-era
engine (NintendoBrowser 5.2.0.x) — mapping 613 → the WebKit branch frozen
circa late 2021 **[inference]** — i.e. a five-year-old engine branch with a
large public n-day surface, if the wrapper (NetFront SystemWeb) doesn't
isolate it.

Implication for BarbarismJB: the *delivery* problem is solved (§1, §4); the
*exploitation* problem (ARW → useful native calls under XOM/PAC/CFI) is
exactly the wall pepsipu documented, and his own suggested detour — porting
the fs sysmodule exploit to WebKit so the browser's legitimate fs code paths
trigger the bug — matches our M3/M4 chain direction.

---

## 4. Precedent library — the operational recipe

| Console | Browser surface | Delivery recipe | Notes |
|---|---|---|---|
| **Switch 1 (PegaSwitch 2017; Nereba/Caffeine; PegaScape)** | Hidden WifiWebAuth applet (+ news "Fake News", + webapplet-via-game on 1.0.0) | LAN/PC DNS server on :53 intercepting conntest hosts → plain-HTTP redirect → JS/ROP exploit page; PegaScape ran this as a **public DNS** so users only set one DNS entry | The exact template; archived but complete ([pegaswitch](https://github.com/reswitched/pegaswitch), [PegaScape](https://github.com/noahc3/PegaScape)) **[verified]** |
| **PS4** | Full user-facing WebKit browser | No DNS trickery needed for delivery — self-host plain-HTTP exploit pages (classic hosts: exploit-hosting webroots on :80; DNS used mainly to *block updates*). Userland via WebKit, kernel via chained bugs | ([consolemods PS4 wiki](https://consolemods.org/wiki/PS4:Alternative_Methods_of_Jailbreaking), [alazif exploit-host-http](https://hub.docker.com/r/alazif/exploit-host-http)) **[verified — delivery model]** |
| **PS5** | No user browser; **User's Guide** manual page opens WebKit | **DNS hijack of `manuals.playstation.net` → local HTTPS server with a self-signed cert; user accepts an untrusted-certificate prompt** → exploit page; ELF loader listens on :9020 after exploitation; appcache enables offline reuse | The closest analog to "hidden browser on a locked console" — note PS5's flow *is* https, tolerated because the console accepts self-signed certs there (no pinning). Switch 2's portal is even softer: plain http ([x0rloser/PS5-Exploit-Host](https://github.com/x0rloser/PS5-Exploit-Host)) **[verified]** |
| **Wii/WiiU/3DS (context)** | User-facing browsers | Direct navigation to hosted exploit pages | Covered by the same exploit-host tooling (alazif) **[verified — tooling scope]** |

Common operational recipe distilled: (1) control DNS for the console, (2)
answer the connectivity-check host with a redirect that fails the
"connected" heuristic, (3) serve the payload page over plain HTTP on the
bench host, (4) keep everything else NXDOMAIN/sinkholed so the console never
reaches update/telemetry endpoints, (5) exploit runs in the applet context,
tethered per boot.

---

## 5. BarbarismJB local test rig (offline/LAN)

Goal: reproducible, air-gapped Switch 2 WebKit entry bench — same shape as
the verified public bench, but with our own portal server, telemetry, and
payload staging for the future WebKit chain. Nothing here executes on the
console beyond rendering pages in the portal applet.

### 5.1 Network topologies (pick one)

**A. Dedicated bench AP (recommended — fully offline).** A Linux host (Pi/
laptop) runs `hostapd` + `dnsmasq`; the Switch 2 joins this SSID only. No
upstream. The console is online to *nothing* except the bench.

```
# hostapd.conf (5 GHz or 2.4 GHz WPA2; country code as appropriate)
interface=wlan0
ssid=BARBARISM-BENCH
hw_mode=a          # or g
channel=36
wpa=2
wpa_pairwise=CCMP
wpa_passphrase=<bench passphrase>

# dnsmasq.conf — DHCP + DNS hijack, NO upstream (--no-resolv semantics)
interface=wlan0
bind-interfaces
dhcp-range=192.168.70.50,192.168.70.150,12h
dhcp-option=option:dns-server,192.168.70.10   # the bench host itself

# Answer every name with the bench IP (catch-all sinkhole):
address=/#/192.168.70.10
# Or, mirror the verified bench (answer ctest set, NXDOMAIN the rest):
# address=/ctest.cdn.nintendo.net/192.168.70.10
# address=/ctest.p01.ctest.srv.nintendo.net/192.168.70.10
# address=/conntest.nintendowifi.net/192.168.70.10
# address=/savanna.srv.nintendo.net/192.168.70.10
# server counter-examples: leave everything else unforwarded (no-resolv, no-hosts)
log-queries          # full DNS telemetry of what the console asks for
```

Catch-all (`address=/#/`) is preferred for research: every Nintendo
update/telemetry host lands on our HTTP sinkhole where we can 404 it *and
log it* (see 5.3). The NXDOMAIN variant is cleaner for "console sees no
internet" behavior parity; the verified public bench uses it. Either way,
with no upstream forwarder the console cannot reach Nintendo at all.

**B. Existing home LAN + manual DNS (quickest, matches public tutorials).**
Console: Settings → Internet → (network) → Change Settings → DNS Settings →
Manual → Primary DNS = bench host IP (Nintendo's own support page documents
the manual-DNS steps for Switch 2). Bench host runs dnsmasq bound to :53 on
the LAN with the same `address=` entries, plus `no-resolv` and firewall
rules blocking the console from egress. Restore Automatic DNS after
sessions. This is exactly how the public bench and the Facebook tutorial
operate **[verified — bench; reported — tutorial]**.

**C. Router-level (OpenWrt).** dnsmasq on the router with the same hijack
entries scoped to the console's MAC (`dhcp-host=<mac>,set:switch2` +
`address=` tags), or an nftables DNAT :53→bench. Useful when the bench host
isn't the AP. Mark the console's traffic zone deny-out except to bench.

### 5.2 Portal HTTP server (bench host, port 80)

Route by `Host` header (the applet re-requests the conntest URL as its
initial page — §1.1):

| Host (any of the ctest set) + `/` | Response |
|---|---|
| `ctest.cdn.nintendo.net`, `ctest.p01.ctest.srv.nintendo.net`, `conntest.nintendowifi.net` | **302 Location: `http://<bench>/portal/`** — the missing `X-Organization: Nintendo` header is what flags "captive portal", launching/navigating the applet; the redirect chain is then followed inside the applet (verified live behavior, §1.2(2)) |
| `<bench>` `/portal/` | 200 `text/html; charset=utf-8` — the payload page (5.4), `Cache-Control: no-store` |
| `<bench>` `/report` (POST) | 200, JSON logged (probe results, UA, engine features) |
| `<bench>` `/stage/*` | binary payload chunks (future exploit stages), `Content-Type: application/octet-stream` |
| anything else | 404 + log (sinkhole telemetry: update pings, telemetry hosts the console tries) |

Serving process must bind :80; drop privileges after bind (the public
entry script does exactly this). Keep **everything plain HTTP** — no TLS
anywhere in the rig (verdict §2). Do not send `X-Organization: Nintendo`
on any conntest-host response unless you *deliberately* want the console to
think it's online (useful for one control experiment, then remove).

### 5.3 Telemetry & observability

- `log-queries` in dnsmasq → every hostname the console asks for, in order.
  This is our map of S2 network behavior on 23.0.1 (conntest cadence,
  savanna/idobata, update hosts) — feed `FIRMWARE.md` research.
- HTTP access log with full headers (UA first-hit gives us the on-device
  `WifiWebAuthApplet … NintendoBrowser/5.2.x` string for our firmware).
- `/report` endpoint collecting JSON from the payload page (the public
  bench's loader.js pattern).
- Optional WebSocket console for live JS eval/replay (bench ships
  `ws.html` + `ws_bridge.py`; same idea as CivSwitch's :9026 loop but
  portal-side).

### 5.4 Payload page structure (`/portal/`)

Single self-contained HTML, zero external dependencies (the applet is
NetFront/WebKit 613-era; do not assume modern JS APIs):

```html
<!doctype html><html><head><meta charset="utf-8">
<title>Network sign-in</title></head>          <!-- look like a portal -->
<body>
<div id="s">starting…</div>
<script>
  // 1. beacon: who are we running in
  var R = {
    ua: navigator.userAgent,                   // expect WifiWebAuthApplet/AppleWebKit/613.0-era
    url: location.href,
    t: Date.now(),
    engine: { jsc: typeof WebAssembly, proxy: typeof Proxy,
              offscreen: typeof OffscreenCanvas }   // feature matrix probes
  };
  // 2. exploit-relevant capability probes (extend per research phase):
  //    - fetch/XHR to /stage/* (staged payload fetch works?)
  //    - @font-face load + measure (GPOS-style parser reachability)
  //    - ArrayBuffer/ DataView groom helpers
  // 3. report + retry loop
  function post(){ fetch('/report',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(R)}).catch(function(){setTimeout(post,2000)}); }
  post();
</script></body></html>
```

Page flow: portal page → probes → `/report` → (later) staged WebKit exploit
fetch from `/stage/*`. Everything no-store so each conntest cycle re-runs
cleanly. Trigger ritual on console: join bench SSID (topology A) or set
manual DNS (B) → Settings → Internet → Connect to This Network / run the
connection test → portal applet opens on our page → "+" (Information)
shows the URL it loaded (the NintendoSoup-inspectable field) → Home to
dismiss when done.

### 5.5 Session hygiene

- Firmware pinned: keep the bench console on 23.0.1; never join a real
  network with it in a modified state (matches community guidance in the
  `1xeg1mt` thread: offline, delete other saved networks **[reported]**).
- Restore Automatic DNS after every session (topology B).
- Sinkhole (not forward) all non-bench DNS so no accidental update check.
- This rig touches only our own hardware on our own LAN; the portal applet
  is used exactly as Nintendo designed it (rendering a LAN captive portal).

---

## 6. Ranked delivery-mechanism conclusion

| Rank | Mechanism | Evidence weight |
|---|---|---|
| **1** | **DNS hijack of plain-HTTP conntest/ctest hosts on the LAN → 302 → attacker `http://` page in WifiWebAuthApplet** | pepsipu primary-source ("custom WiFi captive portal") + verified public S2 bench + June-2025 community WIP + SwitchBrew mechanics + switchbru-on-23.0.1 report. This is the mechanism; adopt it. |
| 2 | News-applet webjump (S1 "Fake News" lineage) | S2 news applet exists but jump list is whitelist-governed and content is Nintendo-sourced https → needs infra compromise, not LAN research. Park. |
| 3 | Login/Share/ShopN/OpenWeb applets | Whitelists + https + cert error codes → dead. |
| 4 | Manual/"Health & Safety" web surface | One GBAtemp remark, undocumented on S2 **[unverified]** — investigate only as a curiosity during bench telemetry. |

**Pinning verdict:** no SSL/TLS break is required for mechanism #1 — the
conntest and the portal page are plain HTTP by design; pinning does not
exist anywhere in the documented applet stack, and the only TLS-relevant
hardening (Upgrade-Insecure-Requests header) does not block plain-HTTP
loading. All other flows are https+whitelist and are rejected as vectors.

## 7. Open questions

1. **S2 portal applet cert UX** — does the S1 "ignore invalid cert" dialog
   still exist on S2? Moot for our HTTP flow, but one bench experiment
   (serve an https:// redirect) answers it. 
2. **Engine freshness** — is AppleWebKit 613.0 really unchanged through
   23.0.1 (no UA documented past 20.1.1)? Bench first-hit UA capture will
   settle it; if the NetFront SystemWeb wrapper is the real parser surface
   (GPOS bug location suggests so), engine n-days may be unreachable behind
   it.
3. **What exactly did pepsipu's WebKit chain achieve** — his blog says the
   agent only reached "call existing native JS functions" and later Discord
   says "ported… works on 23.0.1"; the delta between those two statements
   (fs-sysmodule-exploit port? cleaner ARW?) is unreleased and unpublished.
   Watch for the community "recreation" effort (`1xiha6i`).
4. **Hold reason** — "on hold" is corroborated; "in favor of an Artemis
   entry" is not. Treat Artemis (demo-save entries) as a parallel, not a
   replacement, until pepsipu or a mirror states it.
5. **switchbru registration wall on 23.0.1** (flopsy, GBAtemp) — suggests
   third-party portal DNS services noticed behavior changes on 23.0.1;
   check whether anything in the portal flow changed beyond that service's
   own policy.
6. **conntest host set on S2 23.0.1** — the public bench intercepts three
   hosts (+savanna/idobata); our dnsmasq `log-queries` will produce the
   authoritative list for our unit/firmware.
7. **XOM/PAC/CFI wall** — if our own WebKit chain stalls the same way
   pepsipu's did, his stated detour (port the M3 fs exploit into WebKit's
   legitimate fs code paths, avoiding arbitrary-IPC primitives) is the
   planned fallback and aligns with our existing engine.
