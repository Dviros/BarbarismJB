# The conntest profile matrix — mapping response shapes to console behavior

Live-session ground truth (2026-11-10, console fw **23.0.0**, SDK 23.3.0.0,
static IP .242, DNS = rig): between "console connects" and the
"update the system to continue" screen, the console exchanges exactly TWO
things with the rig — one `A?` query for `ctest.p01.ctest.srv.nintendo.net`
and one `GET /` (Host: ctest.p01…, UA `libcurl (nnNifm; …)`) — repeated in
retry bursts. It asks for **nothing else**: no update servers, no
provisioning hosts, no time hosts. Therefore the ONLY network-side lever
that selects the console's next branch is the shape of our answer to that
single GET. This matrix maps every shape to the observed console screen.

## How to run one profile

```sh
# rig running normally, then per test:
python3 tools/webkit-rig/portal.py --conntest-profile <name> ...   # direct
# or with the launcher: edit/add the flag in its portal command line
```
Each test = change profile → console: re-run the connection test → record
the EXACT screen (photo helps) + what buttons exist. Then next profile.

## The matrix

| profile | response | hypothesis | observed (fw 23.0.0) |
|---|---|---|---|
| `redirect` (default) | 302 → `http://<rig>/portal`, no X-Organization | captive verdict → registration flow | registration + "update to continue" gate; applet never opens |
| `success` | 200 + `X-Organization: Nintendo` | classic online verdict | **TEST** |
| `ok-no-org` | 200 `ok` body, no header | bench's `connectivity_ok` (worked on newest fw → console "online") | **TEST** |
| `redirect-xorg` | 302 → portal **with** X-Organization | does the header outrank the redirect? | **TEST** |
| `redirect-samehost` | 302 → `/portal` (same host, relative) | Apple-style captive shape | **TEST** |
| `no-content` | 204 empty | Android-probe shape | **TEST** |
| `hang` | no answer for 30 s | how does the client classify silence? | **TEST** |

## Observed results (live, fw 23.0.0 console — internal IPs and timestamps redacted, 2026-11-10 evening session)

- `redirect` — captive verdict confirmed; console shows registration screen;
  applet gated behind an update-demand nag (local state set during a brief
  real-DNS window; NO staged package — restart kept 23.0.0).
- `ok-no-org` — console ADVANCES to the online-verification stack
  (api/dauth/sun/beach/dragons/accounts burst) but does not settle as
  online on 23.0.0; verdict treated as inconclusive (test loops).
- `success` — **console goes fully ONLINE through the rig** ("connection
  successful"); entire p01.lp1 boot ceremony enumerated in dns.log;
  dauth/accounts/bvc/sun legs complete TLS handshake with our wildcard
  self-signed cert then send a 7-byte alert + RST = CERT-PINNED.
  eShop under this state: "this feature is not available" (dead account
  stack — the bench observed the same string on a clean console).
- Airplane-cycle mid-online (wedge): returns to registration demand.
- Remaining profiles (redirect-xorg / redirect-samehost / no-content / hang):
  not run — superseded by the success-path findings.

## Where the two walls are (state of the board)

1. CAPTIVE PATH: blocked by the local update-nag (registration → applet).
   Everything else on this path is proven working end-to-end.
2. ONLINE PATH: blocked by TLS cert pinning on the account/dauth stack
   (self-signed wildcard rejected post-handshake every time).

Consequence: on THIS console, tonight, the WebKit applet opens when and only
when the update-nag clears. The nag is not network-servable (its sources are
the same pinned hosts). Options: (a) wait out the nag on a starved network
and retry the registration flow — everything else is armed; (b) clear it from
inside the system, which needs elevation (Civ 7 chain) — which is ALSO the
only way to dump webkit_wkc.nss, the file the bench states is required for
any full-chain engine work on this fw. The WebKit goal and the Civ chain
converge at exactly the same next step.

## What each outcome would mean

- Any profile that opens the **WifiWebAuthApplet** (portal page renders,
  UA `WifiWebAuthApplet…` in portal.log) → WIN; note which shape did it.
- `success`/`ok-no-org` → console goes "online": confirms the console trusts
  our conntest wholesale. Then the question becomes reaching a web applet
  from the online state (other system flows) — separate investigation.
- All redirect shapes gate identically → the gate is verdict-level (any
  captive classification triggers the local update-policy block), not
  shape-level → the fight moves to clearing the console's pending-update
  state (needs elevation or another entry).

## Known facts from tonight (do not re-litigate)

- DNS replies MUST be bench-exact: QR+RD-echo+rcode, AA=0, RA=0, TTL 0
  (dns.py 0.1.7). Anything else → same-ID retransmit storms.
- The console accepts a **private** (RFC1918) A answer for the conntest
  host — no hijack detection.
- libcurl does NOT follow our 302; the system classifies and reacts.
- One DNS server only (secondary `0.0.0.0`); a 90DNS secondary defeats the
  rig's starvation and adds nondeterminism.
