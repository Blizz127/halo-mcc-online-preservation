"""Tests for the P0-C2B capture controls.

These cover the safety properties the rung depends on: default blind-tunnel,
exact-host allowlisting, suffix-spoof rejection, redaction happening before
anything reaches disk, and schema extraction that cannot retain a value.

All fixtures are invented. No captured MCC data exists in this repository — the
rung stopped at Stage A without decrypting anything — so nothing here is derived
from a real response.
"""

import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools" / "interception" / "linux"
sys.path.insert(0, str(TOOLS))

import exclusions  # noqa: E402
import schema_extract  # noqa: E402
from metadata_proxy import ProxyState  # noqa: E402

ALLOWED = "settings.svc.halowaypoint.com"


def _state(mode="terminate", allow=(ALLOWED,)):
    return ProxyState(mode, None, "cert", "key", {h.lower() for h in allow})


# --------------------------------------------------------------------------
# Default blind tunnel / allowlist
# --------------------------------------------------------------------------

def test_default_is_blind_tunnel_when_allowlist_empty() -> None:
    """Forgetting to configure the allowlist must decrypt nothing."""
    state = _state(allow=())
    assert state.should_terminate(ALLOWED) is False
    assert state.should_terminate("anything.example.invalid") is False


def test_tunnel_mode_never_terminates_even_if_allowlisted() -> None:
    state = _state(mode="tunnel")
    assert state.should_terminate(ALLOWED) is False


def test_exact_host_allowlisting_only() -> None:
    state = _state()
    assert state.should_terminate(ALLOWED) is True
    assert state.should_terminate(ALLOWED.upper()) is True
    assert state.should_terminate(ALLOWED + ".") is True


@pytest.mark.parametrize("spoof", [
    "settings.svc.halowaypoint.com.attacker.invalid",   # suffix append
    "evil.settings.svc.halowaypoint.com",               # prefix subdomain
    "settings.svc.halowaypoint.com.evil",               # trailing label
    "xsettings.svc.halowaypoint.com",                   # prefix glue
])
def test_suffix_and_prefix_spoofs_are_rejected(spoof: str) -> None:
    assert _state().should_terminate(spoof) is False


def test_other_mcc_hosts_are_not_terminated_without_being_listed() -> None:
    state = _state()
    for host in ("gamecms-hacs.svc.halowaypoint.com", "halostats.svc.halowaypoint.com",
                 "notification.svc.halowaypoint.com", "mcc-production.azurefd.net"):
        assert state.should_terminate(host) is False


def test_excluded_hosts_are_never_terminated_even_if_allowlisted() -> None:
    """The denylist must win over the allowlist, not the other way round."""
    state = _state(allow=("login.live.com", "xsts.auth.xboxlive.com", ALLOWED))
    assert state.should_terminate("login.live.com") is False
    assert state.should_terminate("xsts.auth.xboxlive.com") is False
    assert state.should_terminate(ALLOWED) is True


def test_empty_host_fails_closed() -> None:
    assert _state().should_terminate("") is False
    assert _state().should_terminate(None) is False


# --------------------------------------------------------------------------
# Pre-disk redaction
# --------------------------------------------------------------------------

def test_header_helper_returns_names_only_never_values() -> None:
    names = exclusions.safe_header_names(["Authorization", "Cookie", "Content-Type"])
    assert names == ["authorization", "content-type", "cookie"]


def test_query_parameter_names_discard_values() -> None:
    names = schema_extract.query_parameter_names("token=SECRETVALUE&flight=abc123&x=1")
    assert names == ["flight", "token", "x"]
    joined = "".join(names)
    assert "SECRETVALUE" not in joined and "abc123" not in joined


def test_path_normalization_replaces_identifier_segments() -> None:
    assert schema_extract.summarize_path("/users/1234567890/settings") == "/users/{id}/settings"
    assert schema_extract.summarize_path(
        "/v1/a1b2c3d4-e5f6-7890-abcd-ef1234567890/config"
    ) == "/v1/{id}/config"
    # Non-identifier segments are preserved so the shape stays meaningful.
    assert schema_extract.summarize_path("/settings/public") == "/settings/public"


@pytest.mark.parametrize("secret", [
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijkl",   # JWT
    "XBL3.0 x=1234567;abcdefghijklmnop",                          # Xbox auth header
    "76561190000000001",                                          # SteamID64-shaped
    "a" * 40,                                                     # long hex-ish blob
])
def test_token_shaped_values_are_redacted(secret: str) -> None:
    assert secret not in exclusions.redact_text(f"prefix {secret} suffix")
    assert exclusions.REDACTED in exclusions.redact_text(secret)


# --------------------------------------------------------------------------
# Schema extraction retains no values
# --------------------------------------------------------------------------

def test_schema_extraction_retains_no_scalar_values() -> None:
    document = {
        "featureFlag": "SUPER_SECRET_FLAG_NAME_VALUE",
        "count": 987654,
        "ratio": 12.5,
        "enabled": True,
        "missing": None,
        "items": ["alpha-secret", "beta-secret"],
    }
    schema = schema_extract.extract_schema(document, "synthetic")
    blob = json.dumps(schema)
    for leaked in ("SUPER_SECRET_FLAG_NAME_VALUE", "987654", "12.5", "alpha-secret", "beta-secret"):
        assert leaked not in blob, f"schema leaked a value: {leaked}"
    # Structure is still described.
    assert schema["type"] == "object"
    assert set(schema["properties"]) == set(document)
    assert schema["properties"]["count"]["type"] == "integer"
    assert schema["properties"]["items"]["element_types"] == ["string"]


def test_sensitive_key_names_are_flagged_and_marked_unresolved() -> None:
    schema = schema_extract.extract_schema(
        {"authToken": "x", "xuid": "y", "correlationId": "z", "colour": "blue"}, "observed"
    )
    for key in ("authToken", "xuid", "correlationId"):
        node = schema["properties"][key]
        assert node.get("sensitive_key_name") is True
        assert node["provenance"] == "unresolved"
    assert "sensitive_key_name" not in schema["properties"]["colour"]


def test_schema_rejects_invalid_provenance() -> None:
    with pytest.raises(ValueError):
        schema_extract.extract_schema({}, "made-up")


def test_deeply_nested_input_terminates_as_unresolved() -> None:
    document = current = {}
    for _ in range(40):
        current["next"] = {}
        current = current["next"]
    blob = json.dumps(schema_extract.extract_schema(document, "synthetic"))
    assert "max depth exceeded" in blob


# --------------------------------------------------------------------------
# Synthetic fixture
# --------------------------------------------------------------------------

def test_synthetic_fixture_is_deterministic() -> None:
    schema = schema_extract.extract_schema(
        {"name": "x", "count": 1, "items": ["a", "b"], "on": True}, "synthetic"
    )
    first = schema_extract.synthesize(schema, seed="p0c2b")
    second = schema_extract.synthesize(schema, seed="p0c2b")
    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_synthetic_fixture_differs_by_seed() -> None:
    schema = schema_extract.extract_schema({"name": "x"}, "synthetic")
    assert schema_extract.synthesize(schema, seed="a") != schema_extract.synthesize(schema, seed="b")


def test_synthetic_fixture_contains_no_original_values() -> None:
    document = {"flag": "REAL_PRODUCTION_VALUE", "items": ["REAL_ONE", "REAL_TWO"]}
    schema = schema_extract.extract_schema(document, "synthetic")
    blob = json.dumps(schema_extract.synthesize(schema, seed="p0c2b"))
    for leaked in ("REAL_PRODUCTION_VALUE", "REAL_ONE", "REAL_TWO"):
        assert leaked not in blob
    assert "synthetic-" in blob


def test_synthetic_fixture_preserves_shape() -> None:
    document = {"a": "x", "b": 1, "c": [{"d": True}]}
    schema = schema_extract.extract_schema(document, "synthetic")
    fixture = schema_extract.synthesize(schema, seed="p0c2b")
    assert set(fixture) == {"a", "b", "c"}
    assert isinstance(fixture["b"], int)
    assert isinstance(fixture["c"], list) and isinstance(fixture["c"][0], dict)
    assert set(fixture["c"][0]) == {"d"}


# --------------------------------------------------------------------------
# No raw decrypted body persistence
# --------------------------------------------------------------------------

def test_no_captured_body_artifacts_are_tracked_in_the_repository() -> None:
    """Stage B never ran, so no production body may exist anywhere in evidence."""
    root = Path(__file__).resolve().parents[1]
    evidence = root / "evidence"
    forbidden_suffixes = (".har", ".saz", ".pcap", ".pcapng", ".bin", ".dump")
    offenders = [p for p in evidence.rglob("*") if p.is_file() and p.suffix.lower() in forbidden_suffixes]
    assert offenders == [], f"raw capture artifacts present: {offenders}"


def test_proxy_state_records_no_header_values_field() -> None:
    """The record structure has no place to put a header value."""
    state = ProxyState("tunnel", None, None, None, set())
    state.record({"event": "connect", "target_host": "example.invalid",
                  "connect_header_names": ["host", "authorization"]})
    stored = state.records[0]
    assert "connect_header_names" in stored
    assert not any(k.endswith("_values") or k == "headers" for k in stored)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
