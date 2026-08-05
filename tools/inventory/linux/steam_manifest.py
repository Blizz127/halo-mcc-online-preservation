"""Locate and parse the Steam application manifest for an installed title.

Steam names manifest files `appmanifest_<appid>.acf` and stores them directly
in the `steamapps/` directory that is the parent of `steamapps/common/`. The
appid is not knowable in advance from the install directory name alone, so
this module finds the manifest by matching each `.acf` file's `installdir`
field against the install directory actually being inventoried, rather than
assuming a filename.
"""

from __future__ import annotations

from pathlib import Path

from vdf import parse_file

# Steam records the account that most recently owned/updated this install.
# It is a personal identifier (resolves to a SteamID64) and is never
# reported by this collector.
_DROP_KEYS = {"LastOwner"}


def find_appmanifest(steamapps_dir: Path, install_dir_name: str) -> Path | None:
    steamapps_dir = Path(steamapps_dir)
    for candidate in sorted(steamapps_dir.glob("appmanifest_*.acf")):
        try:
            data = parse_file(candidate)
        except Exception:
            continue
        app_state = data.get("AppState", {})
        if app_state.get("installdir") == install_dir_name:
            return candidate
    return None


def read_appmanifest(path: Path) -> dict:
    data = parse_file(path)
    app_state = dict(data.get("AppState", {}))
    for key in _DROP_KEYS:
        app_state.pop(key, None)
    return {
        "manifest_path": str(path),
        "app_state": app_state,
        "redacted_fields": sorted(_DROP_KEYS),
    }


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("steamapps_dir", type=Path)
    parser.add_argument("install_dir_name")
    args = parser.parse_args()

    manifest_path = find_appmanifest(args.steamapps_dir, args.install_dir_name)
    if manifest_path is None:
        raise SystemExit(f"no appmanifest in {args.steamapps_dir} has installdir={args.install_dir_name!r}")
    print(json.dumps(read_appmanifest(manifest_path), indent=2))
