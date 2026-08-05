# Linux (Bazzite/Steam/Proton) inventory collectors

Read-only collectors for the P0-B rung (`docs/ROADMAP.md` §P0-B: Retail build bank), scoped to
a Bazzite/Steam/Proton install of MCC. Every module here only reads files already on disk; none
of them writes into a Steam-owned directory, the Proton prefix, or the MCC install tree, and
none copies a retail file into this repository.

## Modules

- `vdf.py` — minimal parser for Valve's text KeyValues format (`.acf`, `.vdf`).
- `sanitize.py` — replaces the MCC install root, `$HOME` (in both its symlinked and resolved
  forms), and local Steam account IDs with stable placeholders. Applied once, at the edge,
  right before a collector's output is printed or written — collectors themselves return raw
  data so they stay easy to unit test against real paths.
- `steam_manifest.py` — finds `appmanifest_<appid>.acf` in the `steamapps/` parent directory by
  matching each manifest's `installdir` field, rather than assuming a filename. Drops the
  `LastOwner` field (a personal identifier) before returning.
- `proton_selection.py` — resolves the compat tool from two independent sources: an explicit
  `CompatToolMapping` override in `config.vdf` (per-app or global default), and runtime evidence
  written by Steam itself under `steamapps/compatdata/<appid>/` (`version`, `config_info`) after
  actually running the title. Also locates the Proton prefix directory and lists only its
  top-level entry names (never anything inside `drive_c`).
- `launch_options.py` — reads the `LaunchOptions` field for one target appid from every local
  Steam profile's `localconfig.vdf`. Does not return the file wholesale.
- `file_inventory.py` — SHA-256/size inventory of the install tree, restricted to
  `file_inventory.INCLUDE_EXTENSIONS` (executables, DLLs, config/launcher files, title modules).
  Bulk game assets (maps, textures, audio, video, packed archives) are excluded by extension.
- `system_versions.py` — best-effort host/tool version collection (OS, kernel, Steam package,
  GPU driver, git, Python, PowerShell). Redacts the machine hostname from `uname` output.
- `build_bank.py` — orchestrates all of the above for one MCC install path and returns/writes a
  single sanitized manifest.

## Usage

```bash
python3 tools/inventory/linux/build_bank.py \
  "/path/to/steamapps/common/Halo The Master Chief Collection" \
  -o evidence/p0b1_bazzite_proton_build_bank/MANIFEST.json
```

Run from a checkout of this repository, or add `tools/inventory/linux` to `PYTHONPATH` first —
the modules import each other by bare name (e.g. `import vdf`), not as a package, so they can
also be run individually for one collector's output during investigation.

## Safety notes

- Every module is read-only against the Steam library and MCC install.
- `steam.token`, `registry.vdf`, and any file under a Proton prefix's `drive_c` are never read
  by these collectors.
- Output must be sanitized (via `sanitize.Sanitizer`) before it is committed. `build_bank.py`
  does this automatically; a collector run standalone for ad hoc investigation does not, and its
  output must not be pasted into a committed file unsanitized.
