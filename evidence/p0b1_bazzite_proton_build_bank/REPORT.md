# P0-B1 report: Bazzite/Steam/Proton retail build bank

Scope: `docs/ROADMAP.md` §P0-B ("Record storefront, app/build identifiers, Steam depot manifests
where lawfully available, file hashes, installed DLC/title packages, launch modes, and tool
versions. Do not commit retail files."), narrowed by this task's authorization to the Linux
(Bazzite/Steam/Proton) side only. Native Windows evidence is **P0-B2** and is not started here.

Collection was entirely noninteractive: no Steam window was opened, MCC was not launched, and no
process was started under the Proton prefix. Every finding below comes from files already on
disk. One item — confirming a distinct EAC-disabled Steam launch config — could not be
completed noninteractively and is recorded as pending under "Requires manual interaction" rather
than guessed at.

## Install identity

- Install path (sanitized): `<MCC_INSTALL_ROOT>` — a
  `steamapps/common/Halo The Master Chief Collection` directory under the operator's Steam
  library, given as the task's authorization. The real absolute path is not recorded in this
  report or in `MANIFEST.json`; every collector output is sanitized before being written (see
  "Sanitization" below).
- Steam library `steamapps/` parent: sibling of `steamapps/common/`, located by walking up from
  the install directory, not assumed.

## Claim 1 — Steam appmanifest and app/build identity

**Claim:** The installed title is Steam appid `976730` ("Halo: The Master Chief Collection"),
currently at `buildid` `19905945`, with three installed depots: base depot `976731` and two DLC
depots (`1064225` → DLC appid `1064220`, `1064226` → DLC appid `1097224`). `halo1`–`halo4` title
directories exist but are empty (0 bytes); only `haloreach/` is populated (~14 GiB), matching the
three installed depots.

**Evidence IDs:** `E-P0B1-001` (`evidence/p0b1_bazzite_proton_build_bank/MANIFEST.json` →
`.steam_appmanifest`)

**Reproduction steps:**
1. List `steamapps/appmanifest_*.acf` in the Steam library's `steamapps/` directory (the parent
   of `steamapps/common/`).
2. Parse each with `tools/inventory/linux/vdf.py` and match `AppState.installdir` against the
   install directory name (`Halo The Master Chief Collection`) — do not assume the manifest
   filename encodes the correct appid without checking.
3. Match found at `appmanifest_976730.acf`. Reproduce with:
   `python3 tools/inventory/linux/steam_manifest.py <steamapps_dir> "Halo The Master Chief Collection"`

**Counter-evidence:** None. `AppState.LastOwner` (a SteamID64 — a personal identifier) was
present in the source file and is deliberately dropped by `steam_manifest.read_appmanifest`
before the manifest is ever sanitized or written; it is not committed in any form, redacted or
otherwise.

**Confidence:** High — direct, first-party Steam metadata, cross-checked against the on-disk
directory sizes it should predict (only `haloreach/` populated).

**Authorized next action:** Bank the matching native-Windows Steam manifest under P0-B2 and
compare `buildid`/depot lists for drift.

## Claim 2 — Selected Proton compatibility tool

**Claim:** No explicit per-title or global-default override exists in
`config/config.vdf`'s `CompatToolMapping` (the section is present but empty for this Steam
profile), so MCC runs on whatever Steam Play default is active at launch time. Runtime evidence
— written by Steam only after actually running the title — resolves that default to
**Proton - Experimental**, version file content `11.0-100`
(`steamapps/compatdata/976730/version`), with the tool's own `version` file reading
`1785137693 experimental-11.0-20260724c` and `toolmanifest.vdf` confirming
`compatmanager_layer_name: proton`, `require_tool_appid: 4183110` (the Proton "Steam Linux
Runtime" app id Valve resolves internally, present as config text only — no app of that id was
installed or inspected under this rung).

**Evidence IDs:** `E-P0B1-002` (`MANIFEST.json` → `.proton_selection`)

**Reproduction steps:**
1. Parse `config/config.vdf`, walk
   `InstallConfigStore.Software.Valve.Steam.CompatToolMapping`; look up appid `976730`, then
   fall back to key `"0"` (global default) — both absent here.
2. Read `steamapps/compatdata/976730/version` and `config_info` (Steam-written runtime state,
   not user configuration). `config_info` line 2 contains an absolute path through
   `steamapps/common/Proton - Experimental/...`, naming the resolved tool directory.
3. Read that directory's own `toolmanifest.vdf` and `version` file to corroborate.
4. Reproduce with: `python3 tools/inventory/linux/proton_selection.py <steam_root> 976730`

**Counter-evidence:** The absence of a `CompatToolMapping` entry means this is evidence of the
*default* tool actually used at last run, not a pinned guarantee that every future launch uses
Proton - Experimental — a Steam client update to the global default, or a future explicit
per-title override, would change it without changing anything recorded here. Re-run this
collector after any such change.

**Confidence:** High for "which Proton build last ran this title" (first-party runtime state,
internally consistent across three independent fields: `version`, `config_info`, and the tool
directory's own version file). Lower for "which tool a hypothetical clean launch would select
today" — that is inherently a client-default lookup this rung did not have to reproduce, since
runtime evidence already answers the narrower and more useful question.

**Authorized next action:** None beyond banking; re-run before any capture rung (P0-C onward) to
confirm the compat tool has not silently changed between rungs.

## Claim 3 — Proton prefix location

**Claim:** The prefix is `steamapps/compatdata/976730/pfx/`, confirmed by more than
directory-name convention: `steamapps/compatdata/976730/config_info` and `version` (Claim 2)
were written into that same numbered directory by the Proton run itself, and
`steamapps/compatdata/976730/tracked_files` (88 KB) lists file paths matching MCC's own retail
Windows layout (e.g. `drive_c/Program Files/Common Files/...`), not a placeholder or another
title's prefix.

**Evidence IDs:** `E-P0B1-002` (`MANIFEST.json` → `.proton_selection.runtime_evidence`)

**Reproduction steps:** Listed above under Claim 2; the prefix directory's top-level entries
(`dosdevices`, `drive_c`, `system.reg`, `user.reg`, `userdef.reg`, `.update-timestamp`,
`creation_sync_guard`) are recorded in `MANIFEST.json`. Nothing inside `drive_c` was read or
enumerated beyond its immediate children (`ProgramData`, `Program Files`, `Program Files (x86)`,
`users`, `vrclient`, `windows`, `openxr`) — no user-generated or per-account content within the
prefix was inspected.

**Counter-evidence:** None.

**Confidence:** High.

**Authorized next action:** None under P0-B1. A later capture rung may need to read
prefix-relative log paths (e.g. Proton's own stdout/stderr redirection); that is out of scope
here.

## Claim 4 — File hash inventory

**Claim:** 90 files across the install tree match the authorized categories (executables, DLLs,
configuration/launcher files, title modules) and were hashed with SHA-256 without copying any
file into this repository. Extension breakdown: 44 `.dll`, 18 `.json`, 16 `.xml`, 5 `.exe`,
2 `.bond`, 1 each of `.config`, `.txt`, `.cer`, `.conf`, `.vdf`. Per-locale EAC strings
(`easyanticheat/localization/*.cfg`, 18 files) and third-party license text
(`easyanticheat/licenses/*.txt`) were deliberately excluded by directory, not by omission —
`tools/inventory/linux/file_inventory.py`'s `EXCLUDE_DIR_NAMES` says why. Bulk game assets
(`.pak`, `.map`, `.bin`, `.png`, `.mvar`, `.gfx`, `.bk2`, `.fsb`, `.uasset`, `.tag`, `.dat`, 632+
files, gigabytes) were excluded by not being in the include list at all — they are large,
copyrighted, and not needed to establish build identity.

Selected hashes (full list in `MANIFEST.json` → `.file_inventory.entries`):

| Relative path | Size (bytes) | SHA-256 |
|---|---:|---|
| `mcclauncher.exe` | 3,946,736 | `e86f518b447a90790f8458bd7be36bc42ae3cdaf723e6b9efcdcea3b544fd95c` |
| `MCC/Binaries/Win64/MCC-Win64-Shipping.exe` | 67,179,480 | `be70d6dcd1a884f10ceb342a7a2dcb35ee0fa43181b66a1d19c3d830e9834691` |
| `haloreach/haloreach.dll` | 13,229,016 | `738dd2d24ea3aea12e1ee9aa4a61094bf116027d42004c35a19e5048608b0894` |
| `easyanticheat/easyanticheat_eos_setup.exe` | 964,336 | `652761ed1fa44955ffde4c3daeb0654937f7cdef7a3a05ddf509c2e707f46e0d` |
| `Engine/Binaries/Win64/UnrealCEFSubProcess.exe` | 3,693,568 | `0499c4073b070710da3cf39ecb7abae803a8dfbe74fb2a5d7b81bbd146c46f49` |
| `easyanticheat/Certificates/base.cer` | 1,165 | `d0e935f5e985abd4816e7094e7ffee6082d7b8de868acb10ac20442190df4eec` |
| `build_tag.txt` | 41 | `d6ea923fe4ba80beb4adc053740adaf74801eda65c62f94410837f03adb8c693` |

**Evidence IDs:** `E-P0B1-004` (`MANIFEST.json` → `.file_inventory`)

**Reproduction steps:**
1. `python3 tools/inventory/linux/file_inventory.py <mcc_root>` — walks the tree, filters by
   `INCLUDE_EXTENSIONS`, hashes with `hashlib.sha256` in 1 MiB chunks.
2. Cross-checked one entry against the system tool independently:
   `sha256sum "<mcc_root>/MCC/Binaries/Win64/MCC-Win64-Shipping.exe"` returned the identical
   digest shown above.

**Counter-evidence:** None found. The include-list is a deliberate scope boundary, not a claim
that no other file is "important" — see Claim 4's category list above for what was excluded and
why.

**Confidence:** High — SHA-256 is a direct cryptographic digest of file bytes, independently
verified against `sha256sum` for the primary game executable.

**Authorized next action:** Compare against the P0-B2 native-Windows hash set for the same
`buildid` to check for any Proton-side file substitution (there should be none — Proton runs the
unmodified Windows binary).

## Claim 5 — Steam launch options (normal vs. EAC-disabled)

**Claim:** Across every local Steam profile on this machine (one profile found), appid `976730`
has **no custom `LaunchOptions` set** — confirmed both by direct lookup for `976730` and by a
sweep across all 646 apps configured on the profile, none of which has any `LaunchOptions` key at
all, ruling out a parsing miss. This means the currently configured launch mode is Steam's
default: no user-supplied Proton/game launch arguments layered on top of `mcclauncher.exe`. The
installed `easyanticheat/settings.json` (`hide_gui: "true"`, `hide_bootstrapper: "false"`) shows
the EAC bootstrapper is configured to run silently but does run — consistent with EAC enabled
under the default launch, not disabled.

**Evidence IDs:** `E-P0B1-005` (`MANIFEST.json` → `.steam_launch_options`), `E-P0B1-007`
(`MANIFEST.json` → `.identity_files["easyanticheat/settings.json"]`)

**Reproduction steps:**
1. Enumerate `userdata/<accountid>/config/localconfig.vdf` for every numeric directory under
   `userdata/`.
2. Parse and look up `UserLocalConfigStore.Software.Valve.Steam.apps.976730.LaunchOptions`.
3. Reproduce with: `python3 tools/inventory/linux/launch_options.py <steam_root> 976730`

**Counter-evidence / gap — EAC-disabled mode not confirmed:**
`docs/ARCHITECTURE_HYPOTHESES.md` H-012 already tracks "MCC officially supports launching on PC
with Easy Anti-Cheat disabled" as **Unproven**, sourced from public MCC support documentation
context, not from local evidence. This rung looked for local, noninteractive confirmation and
did not find one it could stand behind:
- Steam's local per-app metadata cache (`appcache/appinfo.vdf`, ~8 MB, all apps) contains the
  literal bytes for appid `976730` in 78 places; clustering nearby offsets narrows this to one
  ~139 KB region that also contains confirmed MCC-specific strings (`MCC - Reach (Content
  Pack 2)`, `MCC - Reach: Extended Language Pack`). However, this file has no public
  documentation of its binary layout, and a naive string scan of that region *also* surfaced
  strings belonging to an unrelated neighboring app (`NewWorldLauncher.exe`, "EAC runtime") —
  i.e., raw byte-offset proximity is not a reliable app boundary. Reporting an "EAC-disabled
  launch config" claim built on that contaminated extraction would not meet this project's
  evidence bar, so no such claim is made. Correctly isolating one app's block would require
  implementing Valve's binary KeyValues (appinfo) format, which is out of scope for this rung.
- The commonly cited public mechanism for MCC's EAC-disabled mode is a Steam client **Betas tab**
  selection (not a launch-options string), which requires opening the Steam GUI — see "Requires
  manual interaction" below.

**Confidence:** High for "normal launch is the only configured mode right now." Not assessed —
correctly left `Unproven` — for how EAC-disabled mode is actually toggled for this title; H-012
is unchanged by this rung.

**Authorized next action:** Under a future rung, open Steam's Properties → Betas UI for appid
976730 (interactive) and record whatever branch list is shown, or replace the appinfo.vdf
heuristic above with a real binary-KeyValues parser if this project decides that engineering cost
is worth it before then.

## Environment and tool versions

**Evidence IDs:** `E-P0B1-006` (`MANIFEST.json` → `.host_and_tool_versions`)

| Component | Version |
|---|---|
| Bazzite | 44.20260801.0 (Kinoite), image `bazzite-nvidia-open-44.20260802`, build `Stable (F44.20260802)` |
| Kernel | `7.1.5-ogc5.1.fc44.x86_64` (hostname redacted to `<HOSTNAME>`) |
| Steam (RPM package) | `steam-1.0.0.87-1.fc44.x86_64` |
| Proton | Proton - Experimental, `experimental-11.0-20260724c` (see Claim 2) |
| GPU 0 (integrated) | Intel(R) Graphics (ARL), Mesa 26.1.6 |
| GPU 1 (discrete) | NVIDIA GeForce RTX 5070 Ti Laptop GPU, driver `610.43.03` |
| Git | 2.55.0 |
| Python | 3.14.6 |
| PowerShell | Not installed on this host (`null` — expected on native Linux; PowerShell evidence belongs to P0-B2) |
| `sha256sum` | GNU coreutils 9.10 |
| Inventory tooling | `tools/inventory/linux/` at this commit (see Git status below) |

**Reproduction steps:** `python3 tools/inventory/linux/system_versions.py`

**Confidence:** High — direct tool/`--version` output and `/etc/os-release`, with the machine
hostname deliberately redacted (not required for reproduction, and not worth retaining as a
personal-ish identifier).

## Build identity (non-secret)

**Claim:** The retail build embeds these non-secret application-identity values, recorded
verbatim because `docs/EVIDENCE_POLICY.md` explicitly allows "non-secret metadata" and these are
application/service identifiers, not credentials, sessions, or per-user tokens:

- `app.config`: `xal.title_id = 1144039928`, `xal.service_config_id =
  77290100-225e-4768-9373-98164430a9f8`, `xal.client_id = 000000004825FC1F`, `steam.app_id =
  976730`.
- `easyanticheat/settings.json`: `deploymentid = 2aa549857cb249f59a569bafdbb6c693`, `sandboxid =
  185b73671d864906abe776c925b35a38`, `productid = 65f3348d248347a5bd809372b15cf268`, `executable
  = MCC\Binaries\Win64\MCC-Win64-Shipping.exe`.
- `build_tag.txt`: `2025.08.16.178512.1-Release` / `Release`.

**Evidence IDs:** `E-P0B1-007` (`MANIFEST.json` → `.identity_files`)

**Counter-evidence:** None of these values are OAuth/Xbox user/XSTS/Spartan/session/refresh
tokens, passwords, cookies, or private key material — the forbidden categories in
`docs/EVIDENCE_POLICY.md`. They are fixed per-build/per-title identifiers shipped identically to
every retail installation of this build, comparable in kind to a public OAuth *client* ID rather
than a token issued to this account.

**Confidence:** High — read directly from the shipped files, full byte-for-byte content
recorded, no derivation.

**Authorized next action:** These identifiers may become useful under P0-D/P0-E (endpoint and
auth-flow inventory) as the `client_id`/`service_config_id` MCC's XAL layer presents when calling
Microsoft/Xbox services — not evaluated further here, since that is out of this rung's scope.

## Requires manual interaction (not performed under this rung)

These items need an interactive GUI action or a game/process launch, which this task's
authorization did not extend to (`docs/PHASE_0_BOOTSTRAP.md` "Stop conditions": no capture
execution or tool installation beyond what P0-B1 explicitly scopes). Recorded here so they are
not silently dropped:

1. **Steam Properties → Betas tab for appid 976730** — would show whatever beta/branch list
   Steam's client currently offers for this title (e.g., an EAC-disabled branch, if one exists),
   resolving the Claim 5 gap directly instead of via appinfo.vdf byte-scanning. Requires opening
   the Steam GUI.
2. **A confirmed EAC-disabled launch** — to observe what actually changes at runtime (process
   list, EAC bootstrapper behavior) versus the normal launch recorded in Claim 5. Requires
   launching MCC, which was explicitly out of scope for this noninteractive rung.
3. **P0-B2 (native Windows)** — the entire native-Windows side of the P0-B retail build bank
   (Windows Steam client, native Proton-free execution, Windows-side file hashes,
   PowerShell/tool versions on that machine) remains **pending** and unauthorized under this
   task, exactly as `docs/PHASE_0_BOOTSTRAP.md` marks it.

## Sanitization

All output in `MANIFEST.json` was produced by `tools/inventory/linux/build_bank.py`, which routes
every value through `tools/inventory/linux/sanitize.py` before it is written:

- The MCC install root → `<MCC_INSTALL_ROOT>`.
- The operator's home directory (in both its symlinked `$HOME` form and its `os.path.realpath`
  form — this is an ostree-based distro where `/home` is a symlink to `/var/home`, and paths were
  observed on disk in the fully-resolved form) → `<HOME>`.
- The local Steam account ID directory name under `userdata/` → `<STEAM_ACCOUNT_ID>`.
- Any SteamID64-shaped number (`7656119` + 10 digits) anywhere in output → `<STEAMID64>`, as a
  second, pattern-based safety net beyond the explicit `LastOwner` drop in
  `steam_manifest.read_appmanifest`.
- The machine hostname (`uname` nodename) → `<HOSTNAME>`.

Verified post-generation with a direct grep of the committed `MANIFEST.json` for: the real home
path in both forms, the real Steam account ID, any SteamID64-shaped number, and the machine
hostname — zero matches for all four. `steam.token` (Steam's live session token file) and
`registry.vdf` were never opened by any collector. Nothing under the Proton prefix's `drive_c`
was read.

## Test results

New tests in `tests/test_inventory_linux.py` cover the VDF parser (nesting, comments, duplicate
keys, missing-path lookups), the sanitizer (including the `/var/home` vs `/home` shadowing case
that an earlier draft of this collector got wrong — see "Defect found and fixed" below), the file
hasher's extension/directory filtering, and both manifest/launch-option collectors against
synthetic fixtures (no real retail paths or identifiers in any fixture).

```
.venv/bin/python -m pytest -q
............                                                             [100%]
12 passed in 0.04s
```

Full suite (including the pre-existing `test_repository_contract.py`): **12 passed, 0 failed.**

## Defect found and fixed during this rung

The first working version of `sanitize.Sanitizer` replaced `home` with a single string. On this
host, `Path.home()` returns the unresolved `$HOME` env var (`/home/<user>`), but every path
actually observed on disk from Steam's own files is already in the resolved form
(`/var/home/<user>`, since this distro symlinks `/home` → `/var/home`). Naively replacing only
the unresolved form left `/var<HOME>` in early manifest output — the placeholder landed in the
middle of a still-real path fragment. Fixed by passing both the raw and
`os.path.realpath`-resolved home strings into the sanitizer and replacing the longer/more
specific match first (see
`Sanitizer.__init__`'s length-descending sort). Caught before anything was committed, by grepping
a scratch copy of the manifest for the real home path before writing the final evidence file;
`test_sanitizer_prefers_longer_home_variant_first` now guards against a regression.

## Git status at handoff

Working tree is clean except for the new files this rung adds (staged for the one authorized
commit): `tools/inventory/linux/*`, `tests/test_inventory_linux.py`,
`evidence/p0b1_bazzite_proton_build_bank/{REPORT.md,MANIFEST.json}`. No retail binary, capture,
token, certificate, or personal identifier is present in any tracked file — verified by the greps
recorded under "Sanitization" above plus a full-tree `git diff --stat` review before commit.

## Next gate

P0-B1 (Linux/Bazzite/Proton side of P0-B) is complete for what noninteractive collection can
establish. **P0-B2 (native Windows retail build bank) remains unauthorized and unstarted.**
Per `docs/PHASE_0_BOOTSTRAP.md`, each rung requires its own explicit authorization; this report
does not request or assume authorization for P0-B2, P0-C, or any later rung.
