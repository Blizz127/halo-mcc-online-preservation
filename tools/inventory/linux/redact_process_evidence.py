"""Sanitize free-form process/runtime evidence text (e.g. `ps` snapshots, `/proc` reads)
captured during an interactive rung, before it is written into a committed evidence file.

Unlike the P0-B1 collectors, interactive-launch evidence isn't produced by one of this
package's own functions — it comes from ad hoc `ps`/`/proc` reads taken while a human
operator drives the Steam GUI. This module still routes that text through the same
`sanitize.Sanitizer`, but derives every placeholder value (home, Steam library, MCC
install root, Proton prefix, local account ids) from the live environment rather than
requiring the caller to type any of them — so a real path or account id never has to
appear as a literal argument in a command that invokes this tool.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from launch_options import list_account_ids
from sanitize import Sanitizer


def build_sanitizer(appid: str, install_dir_name: str = "Halo The Master Chief Collection") -> Sanitizer:
    home_raw = str(Path.home())
    home_variants = [home_raw, os.path.realpath(home_raw)]

    steam_library_variants = [f"{h}/.local/share/Steam" for h in home_variants]
    mcc_install_root = f"{os.path.realpath(home_raw)}/.local/share/Steam/steamapps/common/{install_dir_name}"
    proton_prefix_variants = [f"{lib}/steamapps/compatdata/{appid}/pfx" for lib in steam_library_variants]

    steam_root = Path(os.path.realpath(home_raw)) / ".local" / "share" / "Steam"
    account_ids = list_account_ids(steam_root)

    return Sanitizer(
        mcc_install_root=mcc_install_root,
        home=home_variants,
        steam_account_ids=account_ids,
        proton_prefix=proton_prefix_variants,
        steam_library=steam_library_variants,
        account_id_placeholder="<ACCOUNT_IDENTIFIER_REDACTED>",
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("appid")
    parser.add_argument("input", type=Path, help="Raw evidence text file to sanitize")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Defaults to stdout")
    args = parser.parse_args()

    sanitizer = build_sanitizer(args.appid)
    text = args.input.read_text(encoding="utf-8", errors="replace")
    sanitized = sanitizer.text(text)

    if args.output:
        args.output.write_text(sanitized, encoding="utf-8")
        print(f"wrote sanitized text to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(sanitized)
