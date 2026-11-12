# MTP-AUDIT — capmtp.bin static reverse-engineering (fw 23.0.0 JPN)

Full RE report from the dedicated audit pass. Artifacts: /tmp/bjbresearch/fwcode/
capmtp.elf + full.c (Ghidra, all 993 functions); offsets = vaddrs for .text.

## Headline classifications

1. **0x02FE/0x02FF are NOT emitted by capmtp** — exhaustive negative proof (no
   immediates, no tables, no Result-decode path). capmtp only writes standard
   0x2001-0x201F. On internal errors it sends NO container at all. The 0x2FE/
   0x2FF containers are **synthesized by the USB transport layer below capmtp
   (usbsys/dcdmtp transport)** when the engine goes silent. → new static target.
2. **The zombie = a designed cancel-latch**: engine state byte [ctx+1]=2 set at
   0x1e960 (`mov w9,#2; stlrb`) when the event pump sees word 0x4001 (USB cancel
   after the abandoned data phase). While latched, every op bails 0x177AE3 with
   no response. The unlatch at 0x1eca0 exists but EATS one command per unlatch.
   Process-global ⇒ survives host reconnects; console-side restart clears.
3. **No memory corruption in capmtp**: single static transaction object (0x860E8);
   9-slot transfer ring with %9 wrap (record LOSS on 10th push — no count guard
   at 0x24038 — but not OOB); all string copies capped 0xFE; chunk loops bounded.
4. **Nondeterministic CloseSession 0x2004/0x2006 explained**: txid-mismatch check
   (0x1f374) vs length-band check — the txid counter never advances after the
   desync, so which fires depends on check order.
5. **Dispatch table safe**: 10 entries, unsigned compare + clamp; unknown opcodes
   → banded internal errors (0x1776E3 / 0x177EE3) with NO response container.

## Transaction structure (0x860E8, single global)

tx+0x08 session_id | +0x0c txid counter | +0x10 CAS lock | +0x2000 container
buffer | +0x2006 response code | +0x2008 txid echo. OpenSession accepts any
session id in [1,0xFFFFFFFE], sets counter=1. CloseSession requires EXACT
current txid + len 12; success clears session at 0x1f0c8 (→ the in-band recovery
candidate: send CloseSession with the correct live txid).

## Audit-directed live probes (corpus v3 — the decisive six)

1. Full 12-byte capture of a 0x2FF reply (type/txid echo ⇒ where the synthesizer
   sits; then audit usbsys's container writer)
2. Session-id abuse: OpenSession(4)/(0x7FFFFFFF); CloseSession with the exact
   live txid + len 12 — predicted 0x2001 + state clear = working in-band recovery
3. Zombie alternation: repeated GetDeviceInfo while latched — unlatch-eats-one
   predicts ~every other command silently consumed
4. **Cancel injection: container with first u16 = 0x4001 on the command pipe
   latches the zombie INSTANTLY from clean state — the 2-byte repro**
5. Ring saturation: ≥2 abandoned GetObject data phases → watch for a transfer
   that never completes (10th-push record loss, logical not memory)
6. Banded unknowns while zombie (0x1000/0x100B/0x9801/0xFFFF): differing canned
   codes = transport maps engine error bands; identical 0x2FF = transport ignores
   them

## Next static target

**usbsys** (the transport that synthesizes error containers when capmtp is
silent) — its container writer is itself an unaudited parser below the parser.

## Live v3 results (2026-11-11 night, second session)

- **cancel_injection CONFIRMED: 2-byte repro** — container with word0=0x4001
  on the command pipe latches the zombie from CLEAN state in 0.15ms. No
  session, no data phase, no handles. The report's headline artifact.
- **Two-phase zombie decoded via raw capture** (journal
  mtp-libptp-20261111T1855xx): Phase A = canned 0x2FF (fast or 20s); Phase B =
  OUT endpoint hard-dead (writes timeout even post-clear_halt) while IN still
  delivered an ENGINE-AUTHORED response (type=3, txid=2 echo, 0x2009 — the
  abandoned GetObject's closeout). Engine alive mid-zombie — the latch model
  is incomplete; usbsys owns endpoint death + 0x2FF synthesis + the 20s timer.
- **usbsys.bin audit DISPATCHED** (device-mode data path, 0x2FF synthesizer,
  transfer-ring counterpart, memory-safety of the bulk-stream parser — the
  Path-to-userland verdict for the USB lane).

## RESOLUTION (2026-11-12): the "0x2FF synthesizer" is OUR OWN HOST LIBRARY

The mystery codes were never console-authored. libptp2 (the library inside
libmtp, which our C prober links) defines pseudo-codes in ptp.h:1126-1132:
0x2F9 NODEVICE, 0x2FA TIMEOUT, 0x2FB CANCEL, 0x2FC BADPARAM,
0x2FD RESP_EXPECTED, 0x2FE DATA_EXPECTED, 0x2FF IO. Its glue
(libusb1-glue.c:1775-1790) maps USB-layer failures to them:
TIMED_OUT->0x2FA, CANCELLED->0x2FB, STALL->0x2FE,
ERROR/NO_DEVICE/OVERFLOW->0x2FF; a response-where-data-expected also
yields 0x2FE (:1429). The "20-second timer" is USB_TIMEOUT_DEFAULT=20000ms
in the same glue. Every observed code decodes: clean-state GetNumObjects
0x2FE = DATA_EXPECTED; zombie 0x2FF = the IO mapping of the dead OUT
endpoint; fast-vs-late = STALL-vs-wait. The console-side reality that
survives: the engine latch (EP0 CANCEL gate) and Phase-B endpoint death are
real console behavior; the "hidden synthesizer module" does not exist.
MTP lane = persistent-DoS class only. Struck from the live-lead list.
