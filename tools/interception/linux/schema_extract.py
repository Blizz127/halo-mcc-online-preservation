"""Structural schema extraction and deterministic synthetic-fixture generation.

Turns a JSON document into a description of its *shape* — types, key names,
array element types, nullability — while discarding every value. Values are
dropped by construction: no function here returns, stores, or copies a scalar
from the input, so a redaction mistake cannot leak one. Only key *names*, types,
and counts survive.

`synthesize()` then builds a fixture from the schema alone, using invented
values derived from a fixed seed. Because it reads only the schema — never the
original document — a fixture can be committed without carrying any production
data, and re-running it produces byte-identical output.

Provenance marking
------------------
Every field carries one of:

- `observed`   — the key and type were seen in a real captured response
- `inferred`   — deduced from context rather than directly seen
- `synthetic`  — invented by this module; corresponds to nothing real
- `unresolved` — present but not safely characterisable yet

A schema produced from invented input is marked `synthetic` throughout, so it
can never be mistaken for a record of a real service.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

PROVENANCE = ("observed", "inferred", "synthetic", "unresolved")

# Key names that commonly carry identifiers or secrets. A key matching these is
# recorded but flagged, so a later rung must justify it before its value is ever
# considered non-sensitive. Matching is on the key NAME only.
_SENSITIVE_KEY_RE = re.compile(
    r"(token|secret|password|passwd|auth|cookie|session|signature|sig$"
    r"|xuid|gamertag|email|account|userid|user_id|puid|deviceid|device_id"
    r"|correlation|traceid|trace_id|requestid|request_id|nonce|key$)",
    re.IGNORECASE,
)


def _type_name(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def extract_schema(value, provenance: str = "observed", _depth: int = 0) -> dict:
    """Describe the shape of `value`. Never retains any scalar from the input."""
    if provenance not in PROVENANCE:
        raise ValueError(f"provenance must be one of {PROVENANCE}")
    if _depth > 24:
        return {"type": "unknown", "provenance": "unresolved", "note": "max depth exceeded"}

    kind = _type_name(value)
    node: dict = {"type": kind, "provenance": provenance}

    if kind == "object":
        properties = {}
        for key in sorted(value.keys()):
            child = extract_schema(value[key], provenance, _depth + 1)
            if _SENSITIVE_KEY_RE.search(str(key)):
                child["sensitive_key_name"] = True
                child["provenance"] = "unresolved"
                child["note"] = (
                    "key name suggests an identifier or secret; value never recorded and "
                    "must not be treated as non-sensitive without independent evidence"
                )
            properties[str(key)] = child
        node["properties"] = properties
        node["property_count"] = len(properties)

    elif kind == "array":
        node["length"] = len(value)
        element_types = sorted({_type_name(v) for v in value})
        node["element_types"] = element_types
        if value:
            # Describe the first element's shape as representative, and note if
            # the array is heterogeneous rather than pretending it is uniform.
            node["element_schema"] = extract_schema(value[0], provenance, _depth + 1)
            node["homogeneous"] = len(element_types) == 1

    elif kind == "string":
        # Length band only - never the string itself.
        node["length_band"] = "empty" if len(value) == 0 else (
            "short" if len(value) <= 32 else "medium" if len(value) <= 256 else "long"
        )

    return node


def _seeded(seed: str, salt: str) -> str:
    return hashlib.sha256(f"{seed}:{salt}".encode()).hexdigest()


def synthesize(schema: dict, seed: str = "p0c2b", _path: str = "$") -> object:
    """Build a fixture from a schema alone. Deterministic for a given seed.

    Reads only the schema, never an original document, so the result contains
    no production data by construction.
    """
    kind = schema.get("type")

    if kind == "object":
        return {k: synthesize(v, seed, f"{_path}.{k}") for k, v in schema.get("properties", {}).items()}
    if kind == "array":
        element = schema.get("element_schema")
        count = min(int(schema.get("length", 0) or 0), 2)
        if element is None or count == 0:
            return []
        return [synthesize(element, seed, f"{_path}[{i}]") for i in range(count)]
    if kind == "string":
        band = schema.get("length_band", "short")
        if band == "empty":
            return ""
        digest = _seeded(seed, _path)
        return {"short": f"synthetic-{digest[:8]}",
                "medium": f"synthetic-{digest[:24]}",
                "long": f"synthetic-{digest}"}[band]
    if kind == "integer":
        return int(_seeded(seed, _path)[:6], 16) % 10000
    if kind == "number":
        return round((int(_seeded(seed, _path)[:6], 16) % 10000) / 100, 2)
    if kind == "boolean":
        return int(_seeded(seed, _path)[:2], 16) % 2 == 0
    if kind == "null":
        return None
    return None


def summarize_path(path: str) -> str:
    """Normalize a URL path: keep structure, replace identifier-shaped segments."""
    normalized = []
    for segment in (path or "").split("/"):
        if not segment:
            normalized.append(segment)
            continue
        if re.fullmatch(r"[0-9a-fA-F-]{8,}", segment) or segment.isdigit():
            normalized.append("{id}")
        else:
            normalized.append(segment)
    return "/".join(normalized)


def query_parameter_names(query: str) -> list[str]:
    """Parameter NAMES only. Values are discarded and never returned."""
    names = []
    for pair in (query or "").split("&"):
        if not pair:
            continue
        names.append(pair.split("=", 1)[0])
    return sorted(set(names))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file", type=Path)
    parser.add_argument("--provenance", choices=PROVENANCE, default="synthetic")
    parser.add_argument("--seed", default="p0c2b")
    args = parser.parse_args()

    document = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
    schema = extract_schema(document, args.provenance)
    print(json.dumps({"schema": schema, "synthetic_fixture": synthesize(schema, args.seed)}, indent=2))
