import hashlib
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools" / "inventory" / "linux"
sys.path.insert(0, str(TOOLS_DIR))

import file_inventory  # noqa: E402
import launch_options  # noqa: E402
import steam_manifest  # noqa: E402
import vdf  # noqa: E402
from sanitize import Sanitizer  # noqa: E402


def test_vdf_parses_nested_blocks_and_comments() -> None:
    text = """
    "AppState"
    {
        // a comment
        "appid"     "123"
        "installdir"    "Example Game"
        "InstalledDepots"
        {
            "456"
            {
                "manifest"  "789"
            }
        }
    }
    """
    data = vdf.parse(text)
    assert data["AppState"]["appid"] == "123"
    assert data["AppState"]["installdir"] == "Example Game"
    assert data["AppState"]["InstalledDepots"]["456"]["manifest"] == "789"


def test_vdf_duplicate_keys_fold_into_list() -> None:
    data = vdf.parse('"a" "1" "a" "2"')
    assert data["a"] == ["1", "2"]


def test_vdf_get_path_missing_returns_none() -> None:
    data = vdf.parse('"a" { "b" "1" }')
    assert vdf.get_path(data, "a", "missing") is None
    assert vdf.get_path(data, "missing", "b") is None
    assert vdf.get_path(data, "a", "b") == "1"


def test_sanitizer_prefers_longer_home_variant_first() -> None:
    sanitizer = Sanitizer(
        mcc_install_root="/var/home/user/.local/share/Steam/steamapps/common/Example",
        home=["/home/user", "/var/home/user"],
    )
    text = "/var/home/user/.local/share/Steam/steamapps/compatdata/123/version"
    assert sanitizer.text(text) == "<HOME>/.local/share/Steam/steamapps/compatdata/123/version"
    # The shorter variant must not have shadowed the longer one and left a stray "/var".
    assert "/var" not in sanitizer.text(text)


def test_sanitizer_redacts_account_id_and_steamid64() -> None:
    # Synthetic fixture values only — not a real account id or SteamID64.
    sanitizer = Sanitizer(mcc_install_root="", home="", steam_account_ids=["12345678"])
    assert sanitizer.text("userdata/12345678/config") == "userdata/<STEAM_ACCOUNT_ID>/config"
    assert sanitizer.text("owner 76561190000000001 done") == "owner <STEAMID64> done"


def test_sanitizer_value_recurses_into_nested_structures() -> None:
    sanitizer = Sanitizer(mcc_install_root="/root", home="/home/user")
    out = sanitizer.value({"path": "/root/file", "nested": ["/home/user/x", 1, {"p": "/root/y"}]})
    assert out == {"path": "<MCC_INSTALL_ROOT>/file", "nested": ["<HOME>/x", 1, {"p": "<MCC_INSTALL_ROOT>/y"}]}


def test_file_inventory_hash_tree_filters_by_extension_and_excluded_dirs(tmp_path: Path) -> None:
    (tmp_path / "game.exe").write_bytes(b"binary")
    (tmp_path / "asset.pak").write_bytes(b"should not be hashed")
    excluded_dir = tmp_path / "localization"
    excluded_dir.mkdir()
    (excluded_dir / "strings.json").write_text("{}")

    entries = file_inventory.hash_tree(tmp_path)
    paths = {e["relative_path"] for e in entries}

    assert "game.exe" in paths
    assert "asset.pak" not in paths
    assert "localization/strings.json" not in paths
    exe_entry = next(e for e in entries if e["relative_path"] == "game.exe")
    assert exe_entry["sha256"] == hashlib.sha256(b"binary").hexdigest()
    assert exe_entry["size_bytes"] == len(b"binary")


def test_steam_manifest_finds_by_installdir_not_filename(tmp_path: Path) -> None:
    steamapps = tmp_path / "steamapps"
    steamapps.mkdir()
    (steamapps / "appmanifest_111.acf").write_text(
        '"AppState"\n{\n"appid" "111"\n"installdir" "Other Game"\n}\n'
    )
    (steamapps / "appmanifest_976730.acf").write_text(
        '"AppState"\n{\n"appid" "976730"\n"installdir" "Halo The Master Chief Collection"\n'
        # Synthetic SteamID64-shaped value only — not a real account.
        '"LastOwner" "76561190000000001"\n}\n'
    )

    found = steam_manifest.find_appmanifest(steamapps, "Halo The Master Chief Collection")
    assert found is not None
    assert found.name == "appmanifest_976730.acf"

    manifest = steam_manifest.read_appmanifest(found)
    assert manifest["app_state"]["appid"] == "976730"
    assert "LastOwner" not in manifest["app_state"]
    assert "LastOwner" in manifest["redacted_fields"]


def test_steam_manifest_returns_none_when_no_match(tmp_path: Path) -> None:
    steamapps = tmp_path / "steamapps"
    steamapps.mkdir()
    (steamapps / "appmanifest_111.acf").write_text(
        '"AppState"\n{\n"appid" "111"\n"installdir" "Other Game"\n}\n'
    )
    assert steam_manifest.find_appmanifest(steamapps, "Nonexistent Game") is None


def test_launch_options_returns_none_when_key_absent(tmp_path: Path) -> None:
    steam_root = tmp_path
    # "12345678" is a synthetic fixture account id, not a real one.
    config_dir = steam_root / "userdata" / "12345678" / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "localconfig.vdf").write_text(
        '"UserLocalConfigStore"\n{\n"Software"\n{\n"Valve"\n{\n"Steam"\n{\n"apps"\n{\n'
        '"976730"\n{\n"LastPlayed" "123"\n}\n}\n}\n}\n}\n}\n'
    )

    result = launch_options.read_launch_options(steam_root, "976730")
    assert result["12345678"]["launch_options"] is None
    assert result["12345678"]["found_file"] is True


def test_launch_options_returns_value_when_present(tmp_path: Path) -> None:
    steam_root = tmp_path
    config_dir = steam_root / "userdata" / "42" / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "localconfig.vdf").write_text(
        '"UserLocalConfigStore"\n{\n"Software"\n{\n"Valve"\n{\n"Steam"\n{\n"apps"\n{\n'
        '"976730"\n{\n"LaunchOptions" "-eac-nop-loaded"\n}\n}\n}\n}\n}\n}\n'
    )

    result = launch_options.read_launch_options(steam_root, "976730")
    assert result["42"]["launch_options"] == "-eac-nop-loaded"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
