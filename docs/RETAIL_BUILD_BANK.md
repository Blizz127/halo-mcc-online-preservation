# Retail build bank

Summary of the pinned retail MCC build identity across platforms. Raw evidence lives under
`evidence/`; this document is a reader-facing index into it and cites evidence IDs rather than
restating evidence — if a value here and the cited evidence ever disagree, the evidence under
`evidence/` is authoritative and this file is stale and should be corrected.

This file did not exist before P0-B1A; it is created here because `docs/ROADMAP.md` §P0-B calls
for the retail build to be banked and this repository had no single summary of that bank yet
(only the per-rung reports under `evidence/`).

## Linux (Bazzite/Steam/Proton)

- **Platform:** Bazzite (immutable/ostree Fedora-based), Steam (native RPM package), Proton.
- **Rungs:** P0-B1 (noninteractive file/config bank) and P0-B1A (interactive launch validation),
  both against the same install.

| Field | Value | Evidence ID |
|---|---|---|
| Steam appid | `976730` | `E-P0B1-001` |
| Buildid (at P0-B1) | `19905945` | `E-P0B1-001` |
| Installed depots | base `976731` + DLC `1064225`, `1064226` (Halo Reach only; Halo 1–4/ODST not installed) | `E-P0B1-001` |
| Selected Proton | Proton - Experimental (`experimental-11.0-20260724c`) | `E-P0B1-002` |
| Proton prefix | `steamapps/compatdata/976730/pfx` | `E-P0B1-002` |
| File hash inventory | 90 files (executables/DLLs/config/launcher/title module) | `E-P0B1-004` |
| Steam Launch Options | Empty (no override) — confirmed both from config on disk (P0-B1) and directly in the Steam Properties UI (P0-B1A) | `E-P0B1-005`, `E-P0B1A-001` |
| Steam Compatibility tab | No forced-tool override | `E-P0B1A-001` |
| Steam Betas tab | No branch besides the default | `E-P0B1A-001` |
| Build identity (non-secret) | `app.config` XAL `title_id`/`service_config_id`/`client_id`; `easyanticheat/settings.json` deployment/sandbox/product ids; `build_tag.txt` | `E-P0B1-007` |
| Host/tool versions | Bazzite 44.20260801.0, kernel 7.1.5, Steam RPM 1.0.0.87, NVIDIA 610.43.03 | `E-P0B1-006` |

### Launch modes observed (P0-B1A)

- **Normal/default launch:** confirmed end to end — process topology, interactive Microsoft/Xbox
  sign-in, MCC main menu, Halo: Reach mode-select menu, apparent online status, and shutdown
  behavior are all recorded. See `E-P0B1A-003` and `E-P0B1A-005`.
- **EAC-disabled / mod-capable launch:** **not offered** through this title's current Steam
  Properties/Play interface (Launch Options empty, no forced compat tool, no extra Betas branch,
  Play launches directly with no choice menu). See `E-P0B1A-002`. This does not resolve
  `docs/ARCHITECTURE_HYPOTHESES.md` H-012 — it only establishes the mechanism is not exposed
  through this interface, on this build, right now.
- **EAC process/module presence:** no process or loaded module named for EAC/anti-cheat was
  observed at any checkpoint during the normal launch (pre-launch, game start, main menu), despite
  `easyanticheat/settings.json` shipping and naming the same executable as its target. This is a
  static, point-in-time finding, not a claim about EAC's behavior during actual online play (which
  was not exercised). See `E-P0B1A-004`.

## Native Windows (P0-B2)

**Not started.** No native-Windows build identity, file hashes, or launch-mode evidence has been
banked yet. This is the only entry this document is missing to consider the retail build bank
complete for both platforms this project targets.

## How to update this file

Add a new row/section only when a new evidence ID is banked under `evidence/` that pins or
changes build identity, and cite that ID. Do not restate raw evidence values without a citation,
and do not promote a hypothesis to fact here — that only happens in `docs/STATUS.md` §"Accepted
facts", under `docs/EVIDENCE_POLICY.md`'s claim format.
