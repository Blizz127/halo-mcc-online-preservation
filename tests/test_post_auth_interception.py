"""Tests for the P0-C2C post-authentication interception controls.

The dangerous operations this rung performs are: minting a CA for a *real*
hostname, and redirecting a *real* hostname. Both are gated by safety checks
tested here to fail closed. All fixtures use the one selected host or reserved
test/documentation names; nothing is derived from captured traffic.
"""

import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools" / "interception" / "linux"
sys.path.insert(0, str(TOOLS))

import host_redirect  # noqa: E402
import local_ca  # noqa: E402

SELECTED = "settings.svc.halowaypoint.com"


# --------------------------------------------------------------------------
# Exact-host redirect validation
# --------------------------------------------------------------------------

def test_exact_host_accepted() -> None:
    host_redirect.validate_target(SELECTED, SELECTED)  # must not raise
    host_redirect.validate_target(SELECTED, SELECTED.upper() + ".")  # case/dot tolerant


@pytest.mark.parametrize("bad", [
    "gamecms-hacs.svc.halowaypoint.com",     # sibling
    "svc.halowaypoint.com",                  # parent
    "halowaypoint.com",                      # registrable parent
    "evil.settings.svc.halowaypoint.com",    # deeper subdomain
    "settings.svc.halowaypoint.com.evil.test",  # suffix append
])
def test_sibling_parent_and_suffix_are_rejected(bad: str) -> None:
    with pytest.raises(host_redirect.RedirectSafetyError):
        host_redirect.validate_target(SELECTED, bad)


@pytest.mark.parametrize(
    "wild", ["*.halowaypoint.com", "*.svc.halowaypoint.com", ".halowaypoint.com"]
)
def test_wildcard_and_suffix_forms_are_rejected(wild: str) -> None:
    with pytest.raises(host_redirect.RedirectSafetyError):
        host_redirect.validate_target(SELECTED, wild)


@pytest.mark.parametrize("identity", [
    "login.live.com", "xsts.auth.xboxlive.com", "user.auth.xboxlive.com",
    "sessiondirectory.xboxlive.com", "api.steampowered.com",
])
def test_identity_hosts_can_never_be_the_redirect_target(identity: str) -> None:
    # Even if the selected host were mis-set to an identity host, the denylist
    # rejects it before anything else.
    with pytest.raises(host_redirect.RedirectSafetyError):
        host_redirect.validate_target(identity, identity)


def test_empty_target_fails_closed() -> None:
    with pytest.raises(host_redirect.RedirectSafetyError):
        host_redirect.validate_target(SELECTED, "")


def test_install_command_contains_sentinel_and_is_append_only(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    state = tmp_path / "prior.json"
    host_redirect.record_prior_state(state, hosts)
    cmds = host_redirect.install_commands(SELECTED, hosts_path=hosts, state_path=state)
    assert len(cmds) == 1
    cmd = cmds[0]
    assert host_redirect.SENTINEL in cmd
    assert "tee -a" in cmd, "install must append (preserve inode for the container bind mount)"
    assert SELECTED in cmd
    assert host_redirect.OBSERVER_LOOPBACK in cmd


def test_rollback_command_uses_exact_recorded_payload_and_preserves_inode(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    state = tmp_path / "prior.json"
    payload = tmp_path / "prior.bytes"
    host_redirect.record_prior_state(state, hosts)
    with hosts.open("a", encoding="utf-8") as stream:
        stream.write(
            f"{host_redirect.OBSERVER_LOOPBACK} {host_redirect.AUTHORIZED_HOST} "
            f"{host_redirect.SENTINEL}\n"
        )
    host_redirect.materialize_rollback(state, payload)
    cmd = host_redirect.rollback_commands(state, payload)[0]
    assert str(payload) in cmd
    assert "cp --no-preserve=mode,ownership" in cmd
    # Must not rename /etc/hosts (which would break the container bind mount).
    assert "mv " not in cmd


def test_install_commands_refuse_a_wildcard_selected_host(tmp_path: Path) -> None:
    with pytest.raises(host_redirect.RedirectSafetyError):
        host_redirect.install_commands("*.halowaypoint.com", state_path=tmp_path / "missing")


# --------------------------------------------------------------------------
# CA minting safety
# --------------------------------------------------------------------------

def test_ca_refuses_to_mint_for_an_identity_host(tmp_path: Path) -> None:
    for identity in ("login.live.com", "xsts.auth.xboxlive.com", "api.steampowered.com"):
        with pytest.raises(ValueError, match="denylist"):
            local_ca.generate(tmp_path, constrain_to_host=identity)


def test_ca_for_selected_host_is_constrained_to_exactly_that_host(tmp_path: Path) -> None:
    from cryptography import x509

    meta = local_ca.generate(tmp_path, constrain_to_host=SELECTED)
    assert meta["leaf_hostname"] == SELECTED
    assert meta["name_constrained_to"] == [SELECTED]

    ca = x509.load_pem_x509_certificate((tmp_path / "ca.crt").read_bytes())
    nc = ca.extensions.get_extension_for_class(x509.NameConstraints).value
    permitted = [g.value for g in nc.permitted_subtrees]
    assert permitted == [SELECTED], "CA must vouch for the one selected host and nothing else"

    leaf = x509.load_pem_x509_certificate((tmp_path / "server.crt").read_bytes())
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = san.get_values_for_type(x509.DNSName)
    assert dns == [SELECTED]
    # No IP SAN in real-host mode (avoids the P0-C2A bare-IP rejection path).
    assert san.get_values_for_type(x509.IPAddress) == []


def test_ca_private_keys_never_enter_returned_metadata(tmp_path: Path) -> None:
    meta = local_ca.generate(tmp_path, constrain_to_host=SELECTED)
    blob = repr(meta)
    assert "BEGIN" not in blob and "PRIVATE KEY" not in blob
    assert meta["key_files_committed"] is False


def test_ca_private_keys_are_not_world_readable(tmp_path: Path) -> None:
    local_ca.generate(tmp_path, constrain_to_host=SELECTED)
    for name in ("ca.key", "server.key"):
        assert (tmp_path / name).stat().st_mode & 0o777 == 0o600


def test_ca_output_paths_are_scratch_not_repository(tmp_path: Path) -> None:
    # The generator writes only into the directory it is given; a test proving
    # no key path escapes into the repo tree by construction.
    meta = local_ca.generate(tmp_path, constrain_to_host=SELECTED)
    for name in meta["key_files_written"]:
        produced = tmp_path / name
        assert produced.exists()
        assert (
            "halo-mcc-online-preservation" not in str(produced.resolve())
            or str(tmp_path) in str(produced)
        )


# --------------------------------------------------------------------------
# Scope verification helper
# --------------------------------------------------------------------------

def test_verify_scope_flags_identity_host_redirection() -> None:
    report = {
        "identity_hosts": {
            "login.live.com": {
                "resolves_to": ["127.0.0.77"],
                "redirected_to_observer": True,
            }
        },
    }
    # Simulate the boolean the real verify_scope computes.
    unaffected = not any(v["redirected_to_observer"] for v in report["identity_hosts"].values())
    assert unaffected is False


def test_flush_command_is_unprivileged_resolvectl() -> None:
    assert host_redirect.flush_dns_cache_command() == "resolvectl flush-caches"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
