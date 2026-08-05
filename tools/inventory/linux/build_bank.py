"""Orchestrate the P0-B1 Bazzite/Steam/Proton retail build bank.

Combines the other collectors in this package into one sanitized manifest:

- Steam appmanifest lookup (app id, build id, installed depots)
- Selected Proton compat tool (config override + runtime evidence)
- Steam launch options for the title, across every local profile
- SHA-256 inventory of executables/DLLs/config/launcher/title-module files
- Small non-secret build-identity files shipped in the install tree
  (app.config, easyanticheat/settings.json, build_tag.txt)
- Host/tool version evidence

Every path and account identifier in the output is run through
`sanitize.Sanitizer` before being written. Nothing under the Proton prefix's
`drive_c` is read beyond the top-level directory names already reported by
`proton_selection`. No file under `mcc_root` is copied; only its path,
size, and hash are recorded for the include-listed extensions.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import file_inventory
import launch_options
import proton_selection
import steam_manifest
import system_versions
from sanitize import Sanitizer

# Small, non-secret build-identity files worth recording verbatim: title/app
# IDs and EAC deployment identifiers, not credentials. See docs/EVIDENCE_POLICY.md
# "Commit rules" — allowed material includes non-secret metadata.
IDENTITY_FILES = [
    "app.config",
    "build_tag.txt",
    "easyanticheat/settings.json",
]


def _read_identity_files(mcc_root: Path) -> dict:
    out = {}
    for rel in IDENTITY_FILES:
        path = mcc_root / rel
        if path.is_file():
            out[rel] = path.read_text(encoding="utf-8", errors="replace")
    return out


def build(mcc_root: Path) -> dict:
    mcc_root = Path(mcc_root).resolve()
    steamapps_dir = mcc_root.parent.parent
    steam_root = steamapps_dir.parent
    install_dir_name = mcc_root.name

    manifest_path = steam_manifest.find_appmanifest(steamapps_dir, install_dir_name)
    if manifest_path is None:
        raise SystemExit(f"no appmanifest under {steamapps_dir} has installdir={install_dir_name!r}")
    manifest = steam_manifest.read_appmanifest(manifest_path)
    appid = manifest["app_state"]["appid"]

    proton = proton_selection.resolve(steam_root, steamapps_dir, appid)
    launch_opts = launch_options.read_launch_options(steam_root, appid)
    file_hashes = file_inventory.hash_tree(mcc_root)
    identity_files = _read_identity_files(mcc_root)
    versions = system_versions.collect()

    account_ids = list(launch_opts.keys())
    home_env = str(Path.home())
    home_variants = [home_env, os.path.realpath(home_env)]
    sanitizer = Sanitizer(mcc_install_root=str(mcc_root), home=home_variants, steam_account_ids=account_ids)

    return sanitizer.value({
        "rung": "P0-B1",
        "install_dir_name": install_dir_name,
        "steam_appmanifest": manifest,
        "proton_selection": proton,
        "steam_launch_options": launch_opts,
        "file_inventory": {
            "root": str(mcc_root),
            "include_extensions": sorted(file_inventory.INCLUDE_EXTENSIONS),
            "entry_count": len(file_hashes),
            "entries": file_hashes,
        },
        "identity_files": identity_files,
        "host_and_tool_versions": versions,
    })


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mcc_root", type=Path, help="Path to the installed 'Halo The Master Chief Collection' directory")
    parser.add_argument("-o", "--output", type=Path, default=None)
    args = parser.parse_args()

    result = build(args.mcc_root)
    text = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
        print(f"wrote manifest to {args.output}")
    else:
        print(text)
