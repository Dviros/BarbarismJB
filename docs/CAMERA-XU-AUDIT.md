# CAMERA-XU-AUDIT — the Cardputer UVC selector-12 overflow: full escalation map (2026-11-12)

Consolidates the user's live finding + Codex's binary work + our escalation
audit (all read-only; bench changes gated on user approval per standing rule).

## The bug (live-confirmed twice, fresh boots, one-byte A/B)

camera.autogen (fw 23.0.0 JPN, sysmodule 0x70, server of cam:m/cam:s/cam:u)
FUN_00044620: Microsoft XU selector 12 GET_LEN result (accepted <=611) is used
unclamped as the GET_CUR copy length into a 576-byte stack buffer
(+0x446e4 -> FUN_00069ae0 memcpy, no dest-size knowledge at +0x69be4).
588 = clean; 589 = saved LR (PAC-gated retab fail -> 2011-0301 restart).
**Unfixed on 23.5.0** (camera absent from switchbrew's updated-module list).

## Escalation verdict: no code-exec in this binary (all paths closed)

1. **param_6 consumer chain = dead end for corruption.** param_6 is
   ctx+0x920, a 7-float region/e-zoom limit struct. Every hop audited:
   zoom-clamp (FUN_00034360, fcmp-based — NaN falls through, computes only),
   float->int crop (FUN_00039e20, &~1 + negative->0 by construction),
   aspect-fit + hard clamp to sensor dims (FUN_0003a450 -> crop fields
   +0xbc/+0xc0/+0xc4), then either SET_CUR back to the device (selector 11
   max 0x14B, selector 3 0xcB) or a fixed 0x120 erpt/IPC blob. No array
   indexing, no allocation sizing, no GPU/VIC register programming from
   these values anywhere.
2. **Single caller** (FUN_00039520 @ +0x39c2c — the only bl in the binary).
   Post-call disassembly scan of all three exits: zero x28/x25/x29-relative
   accesses. Saved-x29 corruption (L 581-588) is throwaway; x28/x25
   (L 597-611) die at retab. The ONLY live corruption is LR -> PAC fault.
3. **Record-walk bounded inside the buffer**: walk count = floor(L/36) <= 16;
   16 records x 36 = 576 exactly; max byte read = 563. No OOB read oracle.
   Record layout: {id, sub, 5 x u32 coords} at buffer + i*0x24. The loop
   does NOT break on match — LAST matching record wins param_6.
4. **No second door in the XU family**: exactly two GUIDs scanned (MS XU
   0F3F95DC... @0x9a87a; vendor XU 499F26F9... @0x9a86a — the face/region
   XU). All 25 FUN_00069ae0 sites enumerated — only selector 12 GET uses a
   device-supplied length. Every other selector uses compile-time constants.

## What the bug DOES give us

- **Reproducible sysmodule crash on latest retail fw** — H1-grade as-is.
- **The match oracle**: a record matching the negotiated (id,sub) flips the
  ROI-valid flag and drives the zoom path — observable via cam:* IPC or the
  stream crop. 1 bit per (id,sub) per GET_CUR, no crash. The confirmation
  channel for every future camera experiment.
- **cam:* IPC leak channel (hop 8)**: 28 bytes of device-derived floats
  readable by any cam:u/cam:s/cam:m client.

## camera's post-exploitation value (if code exec is ever found)

NPDM: system sysmodule, memory_region 2. Holds nvdrv:s + **vic:u** (the
display compositor path), usb:hs (raw host USB), fsp-srv, erpt:c. 51 svc
incl. MapTransferMemory. A foothold here is a privileged userland position
with GPU/VIC submission and USB-host reach — strong real estate, no kernel.

## Ranked live experiments (designs only — bench changes need user approval)

1. L=577..588 survive-test: prove sub-LR overwrite is harmless (baseline).
2. Match-oracle sweep at L=576: establish the no-crash confirmation channel.
3. NaN/crop-poison via record coords (no overflow): probe the clamp chain.
4. PAC diagnostic at L=589: 1-bit-flip LR experiments to classify the
   2011-0301 fault (PAC-fail vs translation-fail).
5. XU GUID/selector rotation recon: document descriptor-driven surface.

## Sources

Codex results dir (xu-finding-packet.md, camera-binary.md, xu-impact.md,
DEVICE-SETUP-RECORD.md) + this audit's decompile/disassembly work at
/tmp/bjbresearch/camerawork/ (camera.elf, full.c, Ghidra gproj/).
