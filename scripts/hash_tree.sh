#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <input-directory> <output-manifest>" >&2
  exit 2
fi

input="$(realpath "$1")"
output="$2"

if [[ ! -d "$input" ]]; then
  echo "input directory does not exist: $input" >&2
  exit 1
fi

find "$input" -type f -print0 \
  | sort -z \
  | while IFS= read -r -d '' file; do
      hash="$(sha256sum "$file" | awk '{print $1}')"
      size="$(stat -c '%s' "$file")"
      rel="${file#"$input"/}"
      printf '%s  %s  %s\n' "$hash" "$size" "$rel"
    done > "$output"

echo "wrote $output"
