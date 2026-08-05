"""Hash and inventory the retail install tree without copying any file.

Only reads file bytes to compute a digest; never writes into the install
directory and never stages a copy of a retail file anywhere in this
repository. Restricted by extension to the categories the P0-B1 rung was
authorized to record: executables, DLLs, configuration/launcher files, and
title modules. Bulk game assets (maps, textures, audio, video, packed
archives) are deliberately excluded — they are large, copyrighted, and not
needed to establish build identity.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

INCLUDE_EXTENSIONS = {
    ".exe", ".dll",
    ".vdf", ".config", ".conf", ".cfg", ".json", ".xml", ".ini", ".bond",
    ".cer", ".txt",
}

# Directory names that never contain title code/config worth hashing, even
# if a stray file under them happens to match an include extension.
EXCLUDE_DIR_NAMES = {"licenses", "localization"}


def _sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def hash_tree(root: Path, include_extensions: set[str] = INCLUDE_EXTENSIONS) -> list[dict]:
    root = Path(root)
    entries = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in include_extensions:
            continue
        if EXCLUDE_DIR_NAMES & {part.lower() for part in path.relative_to(root).parts[:-1]}:
            continue
        rel = path.relative_to(root).as_posix()
        entries.append({
            "relative_path": rel,
            "size_bytes": path.stat().st_size,
            "sha256": _sha256(path),
        })
    return entries


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=None)
    args = parser.parse_args()

    result = hash_tree(args.root)
    text = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {len(result)} entries to {args.output}")
    else:
        print(text)
