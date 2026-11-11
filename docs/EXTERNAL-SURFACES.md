# EXTERNAL-SURFACES — unburned attack-surface map (fw 23.0.0, 2026-11-11)

From the dedicated recon pass: full NPDM module map of all 91 dump titles
(decompressed NSOs at /tmp/bjbresearch/nso-out/ — capmtp, usb.gen2, hid,
wlan, bsdsocket, eth, camera, bluetooth, ldn, NxSwkbd, sdcard, chat…),
each surface assessed for prior art, attacker-input shape, tractability.

## Ranked (constraint-compliant: no games/eShop/carts/second console)

| # | Surface | Module | Hardware | Prior art | Verdict |
|---|---|---|---|---|---|
| **1** | **USB MTP responder** — Settings → Data Management → Copy to a Computer via USB | **capmtp** 0x1b; engine = `nn::dcdmtp` (3DS-MTP lineage); 462KB decompressed, Ghidra-ready | **the cable already plugged in** | **NONE found** (GBAtemp/System Flaws/switchbrew clean); class proven by TinyUSB MTP CVE-2026-61495 (2026, host-driven OOB write) | **#1 — we are the USB host; drive every opcode/param/data-phase** |
| **2** | **Send-to-Smartphone HTTP server** — Album → send to smartphone: console becomes SoftAP @192.168.0.1 with an HTTP file server | capsrv2 lineage (S1 protocol publicly RE'd: not-an-aardvark/switch-album-import) | none — the Mac JOINS the console's AP | CVE-2026-82079 burned the adjacent class (Sep 2026, proximity QR) | **strong — arbitrary HTTP at a system server, no injection needed** |
| 3 | **DHCP client** | **bsdsocket** 0x12 (strings incl. "DHCP message size exceeded during ParamRequest" — some bounds exist; find where they don't); decompressed bsdsocket.bin ready for static audit | rig + segment (TONIGHT) | zero public Nintendo DHCP bugs | running — dhcp.py shipped |
| 4 | SD/exFAT mount parser (crafted SD image from the Mac) | FS/package2 (not in dump) | none | S1 exFAT corruption history | weakest telemetry |
| 5 | S2 camera UVC + DFU (`nn::cduvc` + `nn::stdfu` — S2-NEW, GameChat-reachable) | camera.autogen 0x70, 793KB decompressed | Pico ~$6 | UDPIH (Wii U) precedent only | tractable with gadget |
| 6 | USB HID descriptor stack | usb.gen2 0x6 (userspace xHCI!) + hid | Pico | S1 decade of badUSB attempts (hardened?) | behind camera |
| 7 | swkbd IME (NxSwkbd 0x1041 "Ounce64") | applet + RomFS dicts | USB kbd | none public | opportunistic |
| 8 | 802.11 OTA (MediaTek MT7961 + wpa_supplicant-derived) | wlan.autogen 0x16 | injection NIC/ESP32 | Broadpwn-class listed "untested on Switch" | parked — needs HW |
| 9 | ldn/lp2p IP-broadcast path (ldnhax class burned TWICE: 21.0.0 + CVE-2026-82079@23.0.0) | ldn 0x18 | rig? | hot class | trigger conditions unverified |
| 10 | BT host stack / NFC / GameChat-libwebrtc (server-mediated) | bluetooth.gen2 / nfc / chat | varies | NFC: 2 recent flaws; webrtc unreachable pre-auth | low/deferred |

## Key cross-cutting facts

- **Nintendo runs an active HackerOne program** ($100–$50k, external
  researchers actively mining these exact surface classes —
  CVE-2026-82079 was one, Sep 2026). Unaudited ≠ uncontested: move fast.
- Crash telemetry on stock S2 is weak (erpt blocked by our 90DNS
  posture) — behavioral oracles (response anomalies, USB teardown,
  re-enumeration) are the practical signal until an fs session exists.
- The rig never passively listened for LAN broadcasts — the segment
  tcpdump settles that (add `-i <iface>` full-capture during idle too).

## capmtp attack plan (PLAN A)

1. Baseline: console starts Settings → Data Management → Manage
   Screenshots/Videos → Copy to a Computer via USB; Mac runs libmtp
   `mtp-detect`; log every container (we are the initiator).
2. Map the accepted opcode set from GetDeviceInfo; then hostile params:
   invalid handles (0 / 0xFFFFFFFF), counts 0/max, saturated u32s,
   partial GetObject offset/length, GetObjectPropList absurd prop
   codes, unrequested data phases, TID reuse/desync, double
   OpenSession, mid-transfer Cancel / USB reset (usb:ds documented
   global-reset = state-machine pressure).
3. Fuzz loop: scripted pyusb initiator mutating {opcode, params,
   data-phase length}; oracle = response anomalies / teardown /
   re-enumeration / fatal screen.
4. Static: Ghidra + repo loader on capmtp.bin; the dcdmtp
   IResponseHandler<> template set marks every dataset decoder — audit
   bounds on each; enumerate the opcode dispatch table.
