# PORTING — the future Windows/Linux rig surfaces

Date: 2026-11-10. Status: **FUTURE WORK — documented, not built.** macOS
(`tools/webkit-rig/launch.py`) is the primary host. Nothing in this file
is implemented; it is the design surface so the eventual ports don't
re-derive the platform facts. When a port lands, update this file to
describe what shipped and delete the stale parts.

The porting unit is `launch.py`'s three seams (see §"What launch.py
abstracts"). `dns.py`, `portal.py`, `portal.html` and `probe-32439.html`
are OS-neutral stdlib/ES5 and port as-is.

---

## Linux — the best long-term bench (real AP mode, fully automatic)

Linux is the only host class where the rig can become **fully automatic
for any joined console**: a real AP with DHCP that hands out our DNS
(option 6), so nobody touches console settings at all.

### Interface + AP layer (replaces macOS Internet Sharing)

- `hostapd` on a Wi-Fi interface that supports AP mode
  (`iw list | grep -A1 'Supported interface modes'`); WPA2-PSK,
  SSID `BARBARISM-BENCH`. Bench config (from the original runbook):

  ```ini
  interface=wlan0
  ssid=BARBARISM-BENCH
  hw_mode=g            # or a for 5 GHz; country code as appropriate
  channel=7            # 36 for hw_mode=a
  wpa=2
  wpa_pairwise=CCMP
  wpa_passphrase=<bench passphrase>
  ```

- `dnsmasq` for DHCP+DNS with **DHCP option 6 = the bench IP** — this is
  the automation win macOS cannot match:

  ```ini
  interface=wlan0
  bind-interfaces
  no-resolv                       # NO upstream DNS, ever
  dhcp-range=192.168.70.50,192.168.70.150,12h
  dhcp-option=option:dns-server,192.168.70.10
  # Either dnsmasq answers the conntest set directly...
  address=/ctest.cdn.nintendo.net/192.168.70.10
  address=/ctest.p01.ctest.srv.nintendo.net/192.168.70.10
  address=/conntest.nintendowifi.net/192.168.70.10
  address=/savanna.srv.nintendo.net/192.168.70.10
  address=/idobata.srv.nintendo.net/192.168.70.10
  # ...or drop those lines and run dns.py on :53 (catch-all mode maps to
  # address=/#/192.168.70.10). Pick ONE authority for 53.
  log-queries
  log-facility=/var/log/dnsmasq-bench.log
  ```

### Redirect layer (replaces the pf anchor)

Services stay unprivileged on 8080/5353; redirect the low ports with
iptables (kernel nat, PREROUTING — applies to forwarded/inbound traffic,
per-interface like the pf anchor):

```sh
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80  -j REDIRECT --to-ports 8080
iptables -t nat -A PREROUTING -i wlan0 -p udp --dport 53  -j REDIRECT --to-ports 5353
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 53  -j REDIRECT --to-ports 5353
# teardown = the matching -D deletes; nothing global is flushed.
```

nftables equivalent (one table, ours only — even closer to the pf-anchor
isolation story):

```
table inet barbarismjb_rig {
  chain prerouting {
    type nat hook prerouting priority -100; iifname "wlan0" tcp dport 80 redirect to :8080
    iifname "wlan0" udp dport 53 redirect to :5353
    iifname "wlan0" tcp dport 53 redirect to :5353
  }
}
# up:   nft -f rig.nft          down: nft delete table inet barbarismjb_rig
```

### Privileges: root vs capabilities

- Everything needs `CAP_NET_ADMIN` (iptables/nft) and the low ports need
  `CAP_NET_BIND_SERVICE` only in direct-bind mode; the redirect design
  exists precisely so the services need neither.
- Prefer a dedicated unit with ambient capabilities over running the
  whole launcher as root:

  ```ini
  # systemd unit sketch
  [Service]
  AmbientCapabilities=CAP_NET_ADMIN
  CapabilityBoundingSet=CAP_NET_ADMIN
  NoNewPrivileges=yes
  ```

  (`capsh --print` to verify; `setcap cap_net_bind_service=+ep` on the
  interpreter is the per-binary alternative if direct 80/53 binding
  returns.)

### Linux-specific gotchas to handle when building

- Wi-Fi chips advertise AP mode more often than they honor it well
  (Intel: fine; Broadcom/Realtek USB: expect pain). Have an Ethernet
  fallback (router-mode equivalent: manual DNS on the console).
- `rp_filter` and conntrack hairpins can eat redirected DNS on some
  distros; if the redirect path misbehaves, bind 53 directly.
- NetworkManager/wpa_supplicant will fight hostapd for the interface —
  `nmcli device set wlan0 managed no` first.

## Windows — the constrained host (no real AP; TCP-only port proxy)

### AP layer: `netsh wlan hostednetwork` is DEAD on Windows 10+

The old SoftAP path (`netsh wlan set hostednetwork mode=allow ssid=...`)
no longer works on modern Windows/driver stacks — drivers report "Hosted
network: No" (check `netsh wlan show drivers`). The replacement is
**Wi-Fi Direct**, which is API-level (Windows.Devices.WiFiDirect), not
netsh-scriptable, and does not interoperate cleanly with arbitrary
client devices like a Switch. Honest conclusion: **there is no
supported one-command Windows AP**. The Windows surface is
router-mode-shaped:

1. Windows machine joins the normal LAN (Ethernet preferred).
2. Console joins the same LAN, manual DNS → the Windows IP.
3. Optional isolation: ICS in reverse is not needed; keep the rig
   LAN-only as on macOS.

If a Wi-Fi-Direct AP ever becomes a requirement, it means writing a small
UWP/WinRT helper — out of scope until the Windows port is real.

### Redirect layer: netsh portproxy is TCP-ONLY

`netsh interface portproxy add v4tov4 listenport=80 connectaddress=127.0.0.1 connectport=8080`
handles the HTTP leg, **but portproxy has no UDP support**, so DNS :53
cannot be proxied this way. Consequences for the port:

- DNS leg: run dns.py-equivalent **privileged directly on 53** (admin
  shell / service account), no redirect; or front it with a UDP-capable
  forwarder. This is the honest Windows design — say so in the launcher's
  preflight instead of pretending.
- Windows Firewall: allow inbound 80/8080/53 on the bench profile only
  (`netsh advfirewall firewall add rule …`), scope=LAN subnet.
- ICS (Internet Connection Sharing) exists but brings its own DHCP/DNS
  proxy — the same conflict as macOS Internet Sharing, with the same
  workaround: manual DNS on the console pointing at the sharing host.

## What launch.py abstracts for the ports (the seams)

The macOS logic is deliberately concentrated behind three swappable
layers; a port replaces them and keeps the rest (services, watcher,
journal, auto-chain, self-test) untouched:

| seam | macOS implementation today | Linux replacement | Windows replacement |
|---|---|---|---|
| InterfaceLayer | `networksetup -listallhardwareports` + `ifconfig` parse; interactive pick; `--interface`/`--ip` | `ip -4 -o addr` parse (+ `iw` for AP capability) | `Get-NetIPAddress` / `netsh interface ipv4 show addresses` parse |
| RedirectLayer | pf anchor load/verify/status/teardown via `sudo pfctl` (never global state) | iptables PREROUTING REDIRECT or nft table (never `iptables -F`) | portproxy (TCP only) + privileged DNS bind; no UDP proxy exists |
| PrivilegeLayer | unprivileged services + sudo'd anchor, with the direct-bind fallback ladder | root vs CAP_NET_ADMIN/CAP_NET_BIND_SERVICE + systemd ambient caps | admin shell / service; UAC prompt where needed |

`--mode list` is the natural first milestone for any port (interface
table + platform's sharing state, no side effects), then router mode,
then the platform's AP story (Linux: hostapd+dnsmasq full-auto; Windows:
documented as unsupported).

Also OS-neutral and reusable verbatim: `dns.py`, `portal.py`
(`--port`/`--bind` flags already exist), both HTML probes, the
`TelemetryWatcher`/`Journal` classes in launch.py, and the `--self-test`
suite (loopback-only by construction — it runs on any OS).
