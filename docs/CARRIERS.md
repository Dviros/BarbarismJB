# CARRIERS — entry-point acquisition map (2026-11-11)

Consolidates the carrier census + the cold-start verdict. The chain itself is
deploy-ready (`docs/CIVSWITCH-RUNBOOK.md`); this doc is about the key.

## Purchasable estate (all browser-verified 2026-11-11)

| Carrier | Price | Status | Class |
|---|---|---|---|
| Nora-HD demo | free | **live, JP eShop** (days-to-live since ARIS) | secondary (planted save) |
| Hamidashi demo | free | **live, JP eShop** | secondary |
| Hamidashi full | ¥1,643 (70% off til Nov 20) | live | secondary; NSO cloud-save plantable |
| Seedsow Lullaby full | ¥2,750 | live | secondary; the mac2jb fs-bridge target |
| Nora-HD full | ¥6,820 | live | secondary |
| Gravity Circuit | $21.99 US | live | secondary; LÖVE/LuaJIT, JankFFI full-ABI native calls, exploit works on current build 1.2.1 (figurophobia/GravCirc-Switch-rce) |
| Civ VII 1.0.0 cart | ~$20-60 scalper | refused by user | **cold-start primary** |
| Gezine reserved input-field games | TBD | undisclosed; held for post-FS-patch | cold-start primary |

## Planting (the wall for every purchasable carrier)

All purchasable carriers fire from a **crafted save**; crafting happens
offline; the only stock channel onto the console is a **hacked Switch 1**
(JKSV restore → official local Save Data Transfer, or NSO cloud for
cloud-enabled full games). mac2jb v0.8.0 installers run over an existing
foothold only. A Switch 2 alone cannot perform the initial restore.

## Cold-start verdict: Artemis in-game crafting — IMPOSSIBLE (proven)

Research pass (launcher/ARIS/editor sources, file:line): the executed bytes
are (1) a ~15-byte script path in the suspend-save caret field — an
engine-authored resume structure gameplay never writes; (2) payload FILES
(inject.iet/core.lua/http.lua) in the save archive — the game's serializer
never creates arbitrary filenames; (3) the three games (Seedsow/Hamidashi/
Nora) are kinetic VNs with **zero text input** — no name entry, no memo,
no continue-codes. No NSO/cloud/friend-S1 shortcut exists (all circular).
Kill chain verified against `seedsow-lua-editor/tools/indexed_save.py`
field layout and the launcher FAQ's own statement.

**The refined hunt spec (active):** the engine HAS the missing gadget —
`dialog` tag with swkbd (`textfieldsize="2048"`) persisting typed strings
into saves + `io.open` write access within `save:/` — both only reachable
post-foothold in these three titles. **Any Artemis-engine game whose
gameplay includes a text-entry feature feeding a script path / filename /
file-content field converts the whole chain to input-only.** Catalog scan
running (Madosoft charage with protagonist name-entry are the prime
suspects — name entry is standard in the genre).

## Chain readiness

Buy + Switch 1 → plant → Artemis Lua / JankFFI foothold → fs bridge →
ns2jb chain → PID1 → ns_ssversion rewrite (`docs/APPLET-GATE-RESEARCH.md`
recipe) → applet on the rig → strike kit (`docs/RIG.md`). The CivSwitch
integration (`docs/CIVSWITCH-INTEGRATION.md`) covers the Civ-class primary
when one materializes (cart or Gezine reserves).
