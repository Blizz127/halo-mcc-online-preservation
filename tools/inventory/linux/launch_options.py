"""Read per-title Steam launch options from every local user profile's localconfig.vdf.

`userdata/<accountid>/config/localconfig.vdf` is keyed by a local numeric
Steam account ID (the low 32 bits of a SteamID64), which is a personal
identifier. This module reads only the single field this project needs
(`LaunchOptions` for one target appid) rather than returning the file
wholesale, and callers must still run the result through
`sanitize.Sanitizer` before it is printed or committed — this module does
not sanitize on its own so it stays easy to unit test.
"""

from __future__ import annotations

from pathlib import Path

from vdf import get_path, parse_file


def list_account_ids(steam_root: Path) -> list[str]:
    userdata_dir = Path(steam_root) / "userdata"
    if not userdata_dir.is_dir():
        return []
    return sorted(p.name for p in userdata_dir.iterdir() if p.is_dir() and p.name.isdigit())


def read_launch_options(steam_root: Path, appid: str) -> dict:
    """Return {account_id: {"launch_options": str | None, "localconfig_path": str}}."""
    results = {}
    for account_id in list_account_ids(steam_root):
        localconfig_path = Path(steam_root) / "userdata" / account_id / "config" / "localconfig.vdf"
        entry = {"localconfig_path": str(localconfig_path), "found_file": localconfig_path.is_file()}
        if entry["found_file"]:
            data = parse_file(localconfig_path)
            app_entry = get_path(data, "UserLocalConfigStore", "Software", "Valve", "Steam", "apps", appid)
            entry["launch_options"] = (app_entry or {}).get("LaunchOptions") if isinstance(app_entry, dict) else None
        else:
            entry["launch_options"] = None
        results[account_id] = entry
    return results


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("steam_root", type=Path)
    parser.add_argument("appid")
    args = parser.parse_args()

    print(json.dumps(read_launch_options(args.steam_root, args.appid), indent=2))
