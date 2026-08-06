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
import ipaddress
import json
import re
import urllib.parse
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
_UUID_RE = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[^@\s/]+@[^@\s/]+\.[^@\s/]+$")
_JWT_RE = re.compile(
    r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}$"
)
_XBOX_AUTH_RE = re.compile(r"^XBL3\.0\s+x=[^;\s]+;.+$", re.IGNORECASE)
_OPAQUE_ALPHABET = re.compile(r"^[A-Za-z0-9_+/=-]+$")


def looks_opaque_identifier(text: str, *, decode_percent: bool = True) -> bool:
    """Conservatively classify identifier/credential-shaped strings.

    This is shared by request-target, hostname, and dynamic-key sanitization.
    The decoded text is used only for classification and is never included in an
    exception or diagnostic.
    """
    candidate = urllib.parse.unquote(text) if decode_percent else text
    if not candidate:
        return False
    if len(candidate) > 64:
        return True
    if (
        _UUID_RE.fullmatch(candidate)
        or _EMAIL_RE.fullmatch(candidate)
        or _JWT_RE.fullmatch(candidate)
        or _XBOX_AUTH_RE.fullmatch(candidate)
    ):
        return True
    if re.fullmatch(r"\d{6,}", candidate) or re.fullmatch(r"[0-9a-fA-F]{12,}", candidate):
        return True
    # A long single token is more likely to be a session/account identifier than
    # useful request-path vocabulary. False positives are intentionally safer.
    if len(candidate) >= 16 and _OPAQUE_ALPHABET.fullmatch(candidate):
        return True
    # Dotted opaque values not matching a strict JWT still fail closed.
    dotted = candidate.split(".")
    return len(dotted) >= 3 and all(
        len(part) >= 6 and re.fullmatch(r"[A-Za-z0-9_-]+", part) for part in dotted
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


def _safe_property_name(key: object, dynamic_index: int) -> tuple[str, bool]:
    text = str(key)
    dynamic = (
        looks_opaque_identifier(text)
        or re.search(r"[/\\?=&\s]", text) is not None
        or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", text)
    )
    return (f"{{dynamic_key_{dynamic_index}}}" if dynamic else text), dynamic


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
        dynamic_count = 0
        for key in sorted(value.keys(), key=lambda item: str(item)):
            child = extract_schema(value[key], provenance, _depth + 1)
            safe_key, dynamic = _safe_property_name(key, dynamic_count + 1)
            if dynamic:
                dynamic_count += 1
                child["dynamic_key_name_redacted"] = True
                child["provenance"] = "unresolved"
            elif _SENSITIVE_KEY_RE.search(str(key)):
                child["sensitive_key_name"] = True
                child["provenance"] = "unresolved"
                child["note"] = (
                    "key name suggests an identifier or secret; value never recorded and "
                    "must not be treated as non-sensitive without independent evidence"
                )
            properties[safe_key] = child
        node["properties"] = properties
        node["property_count"] = len(properties)
        if dynamic_count:
            node["dynamic_key_count"] = dynamic_count

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
        return {
            k: synthesize(v, seed, f"{_path}.{k}")
            for k, v in schema.get("properties", {}).items()
        }
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
        decoded = urllib.parse.unquote(segment)
        if looks_opaque_identifier(decoded, decode_percent=False):
            normalized.append("{id}")
        elif re.fullmatch(r"[A-Za-z][A-Za-z0-9._~-]{0,63}", decoded):
            normalized.append(decoded)
        else:
            normalized.append("{redacted_segment}")
    return "/".join(normalized)


def query_parameter_names(query: str) -> list[str]:
    """Parameter NAMES only. Values are discarded and never returned."""
    names = []
    for pair in (query or "").split("&"):
        if not pair:
            continue
        raw_name = pair.split("=", 1)[0]
        name = urllib.parse.unquote_plus(raw_name)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", name):
            names.append(name)
        else:
            names.append("{redacted_parameter_name}")
    return sorted(set(names))


def normalize_request_target(target: str) -> dict:
    """Return value-free request-target metadata suitable for persistence."""
    # Strip fragments before parsing, including origin-form targets for which
    # urlsplit's absolute-URL behavior does not apply.
    text = (target or "").split("#", 1)[0]
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return {"normalized_path": "/{redacted_segment}", "query_parameter_names": []}
    if parsed.scheme or parsed.netloc:
        path, query = parsed.path, parsed.query
    else:
        path, separator, query = text.partition("?")
        if not separator:
            query = ""
    return {
        "normalized_path": summarize_path(path),
        "query_parameter_names": query_parameter_names(query),
    }


def normalize_http_method(method: str) -> str:
    text = (method or "").upper()
    if re.fullmatch(r"[A-Z]{1,16}", text):
        return text
    return "{redacted_method}"


def normalize_hostname(host: str | None) -> str | None:
    """Keep service-name structure while removing IPs and identifier-shaped labels."""
    if host is None:
        return None
    text = host.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return "{ip_address}"
    labels = []
    for label in text.split("."):
        if looks_opaque_identifier(label):
            labels.append("{id}")
        elif re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            labels.append(label)
        else:
            labels.append("{redacted_label}")
    return ".".join(labels)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json_file", type=Path)
    parser.add_argument("--provenance", choices=PROVENANCE, default="synthetic")
    parser.add_argument("--seed", default="p0c2b")
    args = parser.parse_args()

    document = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
    schema = extract_schema(document, args.provenance)
    result = {"schema": schema, "synthetic_fixture": synthesize(schema, args.seed)}
    print(json.dumps(result, indent=2))
