"""Tests for the P0-C2A interception tooling.

The exclusion denylist is the control that prevented identity traffic from being
decrypted during this rung, so it is tested hardest: fail-closed behaviour,
suffix-boundary matching, and the specific hosts MCC was observed contacting.

All fixtures are synthetic. Reserved documentation ranges (RFC 5737) and
reserved test domains (RFC 6761) only.
"""

import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools" / "interception" / "linux"
sys.path.insert(0, str(TOOLS))

import exclusions  # noqa: E402


# --------------------------------------------------------------------------
# Exclusion denylist
# --------------------------------------------------------------------------

@pytest.mark.parametrize("host", [
    "login.live.com",
    "login.microsoftonline.com",
    "user.auth.xboxlive.com",
    "xsts.auth.xboxlive.com",
    "sisu.xboxlive.com",
    "title.mgt.xboxlive.com",
    "sessiondirectory.xboxlive.com",
    "entitlements.svc.halowaypoint.com",
    "api.steampowered.com",
    "ee38.playfabapi.com",
    "api.epicgames.dev",
    "modules-cdn.eac-prod.on.epicgames.com",
])
def test_identity_and_entitlement_hosts_are_excluded(host: str) -> None:
    """Every host MCC was observed contacting through the proxy must be excluded."""
    assert exclusions.is_excluded(host) is True


def test_exclusion_is_case_and_trailing_dot_insensitive() -> None:
    assert exclusions.is_excluded("LOGIN.LIVE.COM") is True
    assert exclusions.is_excluded("login.live.com.") is True
    assert exclusions.is_excluded("  xsts.auth.xboxlive.com  ") is True


def test_exclusion_matches_on_suffix_boundary_not_substring() -> None:
    # A lookalike must not be mistaken FOR the real identity host...
    assert exclusions.is_excluded("login.live.com.attacker.invalid") is False
    assert exclusions.is_excluded("notlive.com") is False
    # ...while genuine subdomains of an excluded parent stay excluded.
    assert exclusions.is_excluded("something.login.live.com") is True


def test_unknown_auth_subdomain_is_excluded_by_parent_guard() -> None:
    # A newly-appearing auth host under the guarded parent must be excluded
    # by default rather than becoming observable until someone notices.
    assert exclusions.is_excluded("brand-new-thing.auth.xboxlive.com") is True


def test_exclusion_fails_closed_on_empty_or_unknown_host() -> None:
    assert exclusions.is_excluded("") is True
    assert exclusions.is_excluded(None) is True


def test_non_identity_title_service_is_observable() -> None:
    # settings.* is the read-only service the rung would have observed; it must
    # NOT be swept up by the entitlements exclusion.
    assert exclusions.is_excluded("settings.svc.halowaypoint.com") is False
    assert exclusions.is_excluded("gamecms-hacs.svc.halowaypoint.com") is False


# --------------------------------------------------------------------------
# Redaction backstop
# --------------------------------------------------------------------------

def test_redaction_replaces_token_shaped_values() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abcdefghijkl"
    assert exclusions.REDACTED in exclusions.redact_text(f"header {jwt} tail")
    assert jwt not in exclusions.redact_text(jwt)


def test_redaction_replaces_xbox_auth_header_shape() -> None:
    assert exclusions.REDACTED in exclusions.redact_text("XBL3.0 x=1234567;abcdefg")


def test_redaction_replaces_steamid64_and_long_hex() -> None:
    assert exclusions.REDACTED in exclusions.redact_text("owner 76561190000000001")
    assert exclusions.REDACTED in exclusions.redact_text("t=" + "a" * 40)


def test_header_names_helper_lowercases_and_never_takes_values() -> None:
    names = exclusions.safe_header_names(["Authorization", "COOKIE", "content-type"])
    assert names == ["authorization", "content-type", "cookie"]
    # The helper returns names only; there is no code path that accepts a value.
    assert all(":" not in n for n in names)


def test_sensitive_header_set_covers_credential_carrying_headers() -> None:
    for header in ("authorization", "cookie", "set-cookie", "proxy-authorization"):
        assert header in exclusions.SENSITIVE_HEADERS


# --------------------------------------------------------------------------
# Local CA safety properties
# --------------------------------------------------------------------------

def test_local_ca_is_short_lived_and_ca_constrained(tmp_path: Path) -> None:
    import datetime

    from cryptography import x509

    import local_ca

    meta = local_ca.generate(tmp_path, hostname="p0c2a.test", days=2)
    cert = x509.load_pem_x509_certificate((tmp_path / "ca.crt").read_bytes())

    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert lifetime < datetime.timedelta(days=3), "test CA must be short-lived"

    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is True and basic.path_length == 0

    constraints = cert.extensions.get_extension_for_class(x509.NameConstraints).value
    permitted = [g.value for g in constraints.permitted_subtrees]
    assert "p0c2a.test" in permitted, "CA must be name-constrained to the test domain"

    assert meta["key_files_committed"] is False
    # Private keys must never appear in returned metadata.
    assert not any("BEGIN" in str(v) for v in meta.values())


def test_local_ca_private_keys_are_not_world_readable(tmp_path: Path) -> None:
    import local_ca

    local_ca.generate(tmp_path, hostname="p0c2a.test", days=1)
    for name in ("ca.key", "server.key"):
        mode = (tmp_path / name).stat().st_mode & 0o777
        assert mode == 0o600, f"{name} mode {oct(mode)} must be 0600"


def test_wine_trust_refuses_a_long_lived_ca(tmp_path: Path) -> None:
    import local_ca
    import wine_trust

    local_ca.generate(tmp_path, hostname="p0c2a.test", days=365)
    with pytest.raises(SystemExit, match="exceeds"):
        wine_trust.install(tmp_path / "ca.crt", tmp_path, Path("/nonexistent-wine"), tmp_path)


def test_wine_trust_refuses_a_non_ca_certificate(tmp_path: Path) -> None:
    import local_ca
    import wine_trust

    local_ca.generate(tmp_path, hostname="p0c2a.test", days=1)
    # server.crt is a leaf, not a CA.
    with pytest.raises(SystemExit, match="not a CA"):
        wine_trust.install(tmp_path / "server.crt", tmp_path, Path("/nonexistent-wine"), tmp_path)


def test_wine_trust_blob_has_expected_property_header() -> None:
    import struct

    import wine_trust

    blob = wine_trust.serialize_blob(b"DERBYTES")
    prop_id, encoding, length = struct.unpack("<III", blob[:12])
    assert prop_id == wine_trust.CERT_CERT_PROP_ID
    assert encoding == wine_trust.X509_ASN_ENCODING
    assert length == len(b"DERBYTES")
    assert blob[12:] == b"DERBYTES"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
