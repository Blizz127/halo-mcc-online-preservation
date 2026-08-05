"""Resolve which Proton compatibility tool Steam actually used for a title.

Two independent sources are combined, because neither alone is conclusive:

- Steam *configuration* evidence: an explicit per-app (or global "0") entry
  under `InstallConfigStore/Software/Valve/Steam/CompatToolMapping` in
  `config.vdf`. Absence of an entry means the title runs on whatever the
  client's global Steam Play default is at launch time — not "no Proton".
- Steam *runtime* evidence: `steamapps/compatdata/<appid>/version` and
  `config_info`, which Steam writes only after actually running the title
  through a compat tool, and which name the exact tool directory used.

This module never touches the Proton prefix's `drive_c` contents beyond
listing top-level Windows-standard directory names already implied by the
tool itself (`Program Files`, `windows`, `users`, ...); it does not read or
hash anything a user or game wrote inside the prefix.
"""

from __future__ import annotations

import re
from pathlib import Path

from vdf import get_path, parse_file

_COMMON_PATH_RE = re.compile(r"steamapps/common/([^/\r\n]+)/")


def read_compat_tool_mapping(steam_root: Path) -> dict:
    config_path = Path(steam_root) / "config" / "config.vdf"
    if not config_path.is_file():
        return {"config_vdf_path": str(config_path), "found": False, "mapping": {}}
    data = parse_file(config_path)
    mapping = get_path(data, "InstallConfigStore", "Software", "Valve", "Steam", "CompatToolMapping") or {}
    return {"config_vdf_path": str(config_path), "found": True, "mapping": mapping}


def resolve_explicit_override(mapping: dict, appid: str) -> dict | None:
    """Return the per-app entry if set, else the global "0" (all other titles) entry, else None."""
    if appid in mapping and mapping[appid]:
        return {"scope": "per-app", "appid": appid, **mapping[appid]}
    if "0" in mapping and mapping["0"]:
        return {"scope": "global-default", "appid": "0", **mapping["0"]}
    return None


def read_runtime_evidence(steamapps_dir: Path, appid: str) -> dict:
    compatdata_dir = Path(steamapps_dir) / "compatdata" / appid
    result = {
        "compatdata_dir": str(compatdata_dir),
        "exists": compatdata_dir.is_dir(),
        "version_file": None,
        "config_info_lines": None,
        "resolved_tool_dir_name": None,
        "prefix_dir": None,
    }
    if not result["exists"]:
        return result

    version_path = compatdata_dir / "version"
    if version_path.is_file():
        result["version_file"] = version_path.read_text(encoding="utf-8", errors="replace").strip()

    config_info_path = compatdata_dir / "config_info"
    tool_dir_name = None
    if config_info_path.is_file():
        text = config_info_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        result["config_info_lines"] = lines
        for line in lines:
            match = _COMMON_PATH_RE.search(line)
            if match:
                tool_dir_name = match.group(1)
                break
    result["resolved_tool_dir_name"] = tool_dir_name

    pfx_dir = compatdata_dir / "pfx"
    if pfx_dir.is_dir():
        result["prefix_dir"] = str(pfx_dir)
        result["prefix_top_level_entries"] = sorted(p.name for p in pfx_dir.iterdir())

    return result


def read_tool_manifest(steam_root: Path, tool_dir_name: str) -> dict | None:
    if not tool_dir_name:
        return None
    tool_dir = Path(steam_root) / "steamapps" / "common" / tool_dir_name
    manifest_path = tool_dir / "toolmanifest.vdf"
    version_path = tool_dir / "version"
    if not tool_dir.is_dir():
        return None
    out = {"tool_dir": str(tool_dir)}
    if manifest_path.is_file():
        out["toolmanifest"] = parse_file(manifest_path).get("manifest", {})
    if version_path.is_file():
        out["version_file"] = version_path.read_text(encoding="utf-8", errors="replace").strip()
    return out


def resolve(steam_root: Path, steamapps_dir: Path, appid: str) -> dict:
    mapping_info = read_compat_tool_mapping(steam_root)
    explicit = resolve_explicit_override(mapping_info["mapping"], appid)
    runtime = read_runtime_evidence(steamapps_dir, appid)
    tool_manifest = read_tool_manifest(steam_root, runtime.get("resolved_tool_dir_name"))
    return {
        "appid": appid,
        "explicit_config_override": explicit,
        "compat_tool_mapping_present_but_empty": explicit is None and mapping_info["found"] and not mapping_info["mapping"],
        "runtime_evidence": runtime,
        "resolved_tool_manifest": tool_manifest,
    }


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("steam_root", type=Path)
    parser.add_argument("appid")
    args = parser.parse_args()

    steamapps_dir = args.steam_root / "steamapps"
    print(json.dumps(resolve(args.steam_root, steamapps_dir, args.appid), indent=2))
