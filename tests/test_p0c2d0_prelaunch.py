"""Synthetic-only contract tests for P0-C2D0 pre-launch tooling."""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509

TOOLS = Path(__file__).resolve().parents[1] / "tools" / "interception" / "linux"
sys.path.insert(0, str(TOOLS))

import host_redirect  # noqa: E402
import local_ca  # noqa: E402
import p0c2d_preflight  # noqa: E402
import prelaunch_relay  # noqa: E402
import reverse_proxy  # noqa: E402
import schema_extract  # noqa: E402
import tls_observer  # noqa: E402
import upstream_probe  # noqa: E402
import wine_trust  # noqa: E402


def _free_port() -> int:
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def _authorized_hosts_line() -> bytes:
    return (
        f"{host_redirect.OBSERVER_LOOPBACK} {host_redirect.AUTHORIZED_HOST} "
        f"{host_redirect.SENTINEL}\n"
    ).encode()


def test_production_relay_contract_is_exact_and_numeric() -> None:
    address = prelaunch_relay.validate_production_contract(
        "127.0.0.77", "settings.svc.halowaypoint.com", "20.184.144.194", 443
    )
    assert str(address) == "20.184.144.194"
    for bad in ("localhost", "127.0.0.1", "settings.svc.halowaypoint.com"):
        with pytest.raises(prelaunch_relay.RelaySafetyError):
            prelaunch_relay.validate_production_contract(
                "127.0.0.77", "settings.svc.halowaypoint.com", bad, 443
            )
    with pytest.raises(prelaunch_relay.RelaySafetyError):
        prelaunch_relay.validate_production_contract(
            "0.0.0.0", "settings.svc.halowaypoint.com", "20.184.144.194", 443
        )
    with pytest.raises(prelaunch_relay.RelaySafetyError):
        prelaunch_relay.validate_production_contract(
            "127.0.0.77", "SETTINGS.SVC.HALOWAYPOINT.COM.", "20.184.144.194", 443
        )
    repository_log = Path(__file__).resolve().parents[1] / "must-not-be-created.json"
    with pytest.raises(prelaunch_relay.RelaySafetyError, match="outside repository"):
        prelaunch_relay.validate_runtime_paths(
            [repository_log], require_outside_repository=True
        )


def test_blind_relay_half_close_counters_controls_and_safe_log(tmp_path: Path) -> None:
    upstream_port, relay_port = _free_port(), _free_port()
    upstream_ready = threading.Event()

    def upstream_server() -> None:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", upstream_port))
            listener.listen(1)
            upstream_ready.set()
            conn, _ = listener.accept()
            with conn:
                received = b""
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    received += chunk
                assert received == b"synthetic-client-secret"
                conn.sendall(b"synthetic-server-secret")
                conn.shutdown(socket.SHUT_WR)

    upstream_thread = threading.Thread(target=upstream_server)
    upstream_thread.start()
    assert upstream_ready.wait(2)

    ready = threading.Event()
    result: dict = {}
    pid_file = tmp_path / "relay.pid"
    ready_file = tmp_path / "relay.ready"
    log_file = tmp_path / "relay.json"

    def relay_server() -> None:
        result["state"] = prelaunch_relay.serve(
            "127.0.0.1", relay_port, "synthetic.test", "127.0.0.1", upstream_port,
            log_file, 1, 5.0, 2.0, pid_file, ready_file,
            enforce_production=False, ready_event=ready,
        )

    relay_thread = threading.Thread(target=relay_server)
    relay_thread.start()
    assert ready.wait(2)
    assert pid_file.is_file() and ready_file.is_file()
    with socket.create_connection(("127.0.0.1", relay_port), timeout=2) as client:
        client.sendall(b"synthetic-client-secret")
        client.shutdown(socket.SHUT_WR)
        response = b""
        while True:
            chunk = client.recv(1024)
            if not chunk:
                break
            response += chunk
    assert response == b"synthetic-server-secret"
    relay_thread.join(5)
    upstream_thread.join(5)
    assert not relay_thread.is_alive() and not upstream_thread.is_alive()
    assert not pid_file.exists() and not ready_file.exists()
    entry = result["state"].connections[0]
    assert entry["bytes_client_to_upstream"] == len(b"synthetic-client-secret")
    assert entry["bytes_upstream_to_client"] == len(b"synthetic-server-secret")
    persisted = log_file.read_text()
    assert "synthetic-client-secret" not in persisted
    assert "synthetic-server-secret" not in persisted
    assert "client_address" not in persisted


def test_blind_relay_enforces_total_deadline_with_active_connection(tmp_path: Path) -> None:
    upstream_port, relay_port = _free_port(), _free_port()
    upstream_ready = threading.Event()

    def upstream_server() -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", upstream_port))
            listener.listen(1)
            upstream_ready.set()
            conn, _ = listener.accept()
            with conn:
                while conn.recv(1024):
                    pass

    upstream_thread = threading.Thread(target=upstream_server)
    upstream_thread.start()
    assert upstream_ready.wait(2)
    relay_ready = threading.Event()
    result: dict = {}

    def relay_server() -> None:
        started = time.monotonic()
        result["state"] = prelaunch_relay.serve(
            "127.0.0.1", relay_port, "synthetic.test", "127.0.0.1", upstream_port,
            tmp_path / "deadline.json", 1, 0.5, 0.5,
            enforce_production=False, ready_event=relay_ready,
        )
        result["elapsed"] = time.monotonic() - started

    relay_thread = threading.Thread(target=relay_server)
    relay_thread.start()
    assert relay_ready.wait(2)
    client = socket.create_connection(("127.0.0.1", relay_port), timeout=2)
    client.sendall(b"kept-open")
    relay_thread.join(2)
    client.close()
    upstream_thread.join(2)
    assert not relay_thread.is_alive() and not upstream_thread.is_alive()
    assert result["elapsed"] < 1.5
    assert result["state"].connections[0]["error_class"] == "TotalTimeout"


def test_blind_relay_records_upstream_connect_failure_without_worker_escape(
    tmp_path: Path,
) -> None:
    unused_upstream, relay_port = _free_port(), _free_port()
    ready = threading.Event()
    result: dict = {}

    def relay_server() -> None:
        result["state"] = prelaunch_relay.serve(
            "127.0.0.1", relay_port, "synthetic.test", "127.0.0.1", unused_upstream,
            tmp_path / "connect-failure.json", 1, 2.0, 1.0,
            enforce_production=False, ready_event=ready,
        )

    thread = threading.Thread(target=relay_server)
    thread.start()
    assert ready.wait(2)
    with socket.create_connection(("127.0.0.1", relay_port), timeout=2):
        pass
    thread.join(3)
    assert not thread.is_alive()
    assert result["state"].connections[0]["error_class"] == "ConnectionRefusedError"


def _write_control(path: Path, tool: str, kind: str, pid: int, run_id: str = "audit-run") -> None:
    path.write_text(json.dumps({
        "format": prelaunch_relay.CONTROL_FORMAT, "tool": tool, "kind": kind,
        "pid": pid, "run_id": run_id,
    }) + "\n", encoding="utf-8")


def test_relay_removes_only_recognized_stale_controls(tmp_path: Path) -> None:
    ready = tmp_path / "relay.ready"
    _write_control(ready, prelaunch_relay.RELAY_TOOL, "ready", 999_999_999)
    prelaunch_relay.prepare_control_path(ready, prelaunch_relay.RELAY_TOOL, "ready")
    assert not ready.exists()


@pytest.mark.parametrize("kind", ["pid", "ready"])
def test_relay_refuses_active_or_unrelated_control_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    active = tmp_path / f"active.{kind}"
    _write_control(active, prelaunch_relay.RELAY_TOOL, kind, os.getpid())
    monkeypatch.setattr(prelaunch_relay, "_pid_matches_tool", lambda *_args: True)
    with pytest.raises(prelaunch_relay.RelaySafetyError, match="active"):
        prelaunch_relay.prepare_control_path(active, prelaunch_relay.RELAY_TOOL, kind)
    assert active.exists()

    unrelated = tmp_path / "unrelated.ready"
    unrelated.write_text("operator-owned\n", encoding="utf-8")
    with pytest.raises(prelaunch_relay.RelaySafetyError, match="unrelated"):
        prelaunch_relay.prepare_control_path(unrelated, prelaunch_relay.RELAY_TOOL, "ready")
    assert unrelated.read_text(encoding="utf-8") == "operator-owned\n"


def test_relay_publishes_ready_only_after_listen_and_state_initialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relay_port, upstream_port = _free_port(), _free_port()
    original = prelaunch_relay.create_control_file
    observations = []

    def checked_create(path, tool, kind, pid, run_id, extra=None):
        if kind == "pid":
            assert (tmp_path / "relay.json").is_file()
            with socket.create_connection(("127.0.0.1", relay_port), timeout=1):
                observations.append("listener_reachable")
        result = original(path, tool, kind, pid, run_id, extra)
        if kind == "ready":
            document = json.loads(Path(path).read_text(encoding="utf-8"))
            assert document["run_id"] == run_id and document["pid"] == pid
            observations.append("ready_published")
        return result

    monkeypatch.setattr(prelaunch_relay, "create_control_file", checked_create)
    prelaunch_relay.serve(
        "127.0.0.1", relay_port, "synthetic.test", "127.0.0.1", upstream_port,
        tmp_path / "relay.json", 1, 1.0, 0.5,
        tmp_path / "relay.pid", tmp_path / "relay.ready", enforce_production=False,
    )
    assert observations == ["listener_reachable", "ready_published"]


def test_relay_eaddrinuse_creates_no_artifacts(tmp_path: Path) -> None:
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        port = occupied.getsockname()[1]
        paths = [tmp_path / "relay.json", tmp_path / "relay.pid", tmp_path / "relay.ready"]
        with pytest.raises(prelaunch_relay.RelaySafetyError, match="already in use"):
            prelaunch_relay.serve(
                "127.0.0.1", port, "synthetic.test", "127.0.0.1", _free_port(),
                paths[0], 1, 0.5, 0.2, paths[1], paths[2], enforce_production=False,
            )
    assert not any(path.exists() for path in paths)


def test_relay_cleanup_preserves_replaced_ready_file(tmp_path: Path) -> None:
    relay_port, upstream_port = _free_port(), _free_port()
    ready_event = threading.Event()
    ready_path, pid_path = tmp_path / "relay.ready", tmp_path / "relay.pid"
    result = {}

    def server() -> None:
        result["state"] = prelaunch_relay.serve(
            "127.0.0.1", relay_port, "synthetic.test", "127.0.0.1", upstream_port,
            tmp_path / "relay.json", 1, 2.0, 0.5, pid_path, ready_path,
            enforce_production=False, ready_event=ready_event,
        )

    thread = threading.Thread(target=server)
    thread.start()
    assert ready_event.wait(2)
    ready_path.unlink()
    ready_path.write_text("replacement-owned-by-operator\n", encoding="utf-8")
    with socket.create_connection(("127.0.0.1", relay_port), timeout=2):
        pass
    thread.join(3)
    assert not thread.is_alive()
    assert ready_path.read_text(encoding="utf-8") == "replacement-owned-by-operator\n"
    assert not pid_path.exists()


def test_relay_stalled_send_and_worker_are_runtime_bounded(tmp_path: Path) -> None:
    upstream_port, relay_port = _free_port(), _free_port()
    upstream_ready = threading.Event()

    def upstream() -> None:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            listener.bind(("127.0.0.1", upstream_port))
            listener.listen(1)
            upstream_ready.set()
            conn, _ = listener.accept()
            with conn:
                time.sleep(1.0)

    upstream_thread = threading.Thread(target=upstream)
    upstream_thread.start()
    assert upstream_ready.wait(2)
    relay_ready = threading.Event()
    result = {}

    def relay() -> None:
        started = time.monotonic()
        result["state"] = prelaunch_relay.serve(
            "127.0.0.1", relay_port, "synthetic.test", "127.0.0.1", upstream_port,
            tmp_path / "stalled.json", 1, 0.5, 0.25,
            enforce_production=False, ready_event=relay_ready,
        )
        result["elapsed"] = time.monotonic() - started

    relay_thread = threading.Thread(target=relay)
    relay_thread.start()
    assert relay_ready.wait(2)
    with socket.create_connection(("127.0.0.1", relay_port), timeout=2) as client:
        client.settimeout(0.1)
        block = b"x" * 65536
        for _ in range(128):
            try:
                client.send(block)
            except OSError:
                break
    relay_thread.join(2)
    upstream_thread.join(2)
    assert not relay_thread.is_alive() and not upstream_thread.is_alive()
    assert result["elapsed"] < 1.5
    assert result["state"].connections[0]["error_class"] in {
        "TotalTimeout", "TimeoutError", "ServerShutdown", "ConnectionResetError",
    }


def test_redirect_requires_six_safe_ipv4_ipv6_resolutions(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_resolve(host: str, family: int) -> list[str]:
        if host == host_redirect.AUTHORIZED_HOST:
            return [host_redirect.OBSERVER_LOOPBACK] if family == socket.AF_INET else []
        return ["203.0.113.10"] if family == socket.AF_INET else ["2001:db8::10"]

    monkeypatch.setattr(host_redirect, "resolve_family", fake_resolve)
    monkeypatch.setattr(host_redirect, "read_our_entries", lambda: [host_redirect.SENTINEL])
    report = host_redirect.verify_scope(
        host_redirect.AUTHORIZED_HOST, host_redirect.OBSERVER_LOOPBACK,
        host_redirect.IDENTITY_HOSTS,
    )
    assert report["all_checks_pass"] is True
    with pytest.raises(host_redirect.RedirectSafetyError, match="six"):
        host_redirect.verify_scope(
            host_redirect.AUTHORIZED_HOST, host_redirect.OBSERVER_LOOPBACK,
            host_redirect.IDENTITY_HOSTS[:-1],
        )


def test_redirect_duplicate_prevention_and_exact_rollback_record(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    state = tmp_path / "prior.json"
    host_redirect.record_prior_state(state, hosts)
    commands = host_redirect.install_commands(host_redirect.AUTHORIZED_HOST,
                                              host_redirect.OBSERVER_LOOPBACK, hosts, state)
    assert "tee -a" in commands[0]
    assert "stat -c" in commands[0] and "sha256sum" in commands[0]
    inode = hosts.stat().st_ino
    with hosts.open("ab") as stream:
        stream.write(_authorized_hosts_line())
    payload = tmp_path / "prior.bytes"
    host_redirect.materialize_rollback(state, payload)
    command = host_redirect.rollback_commands(state, payload)[0]
    assert "cp --no-preserve=mode,ownership" in command
    assert "stat -c" in command
    with hosts.open("wb") as stream:
        stream.write(payload.read_bytes())
    verified = host_redirect.verify_rollback(state, hosts)
    assert hosts.stat().st_ino == inode
    assert verified == {
        "exact_bytes_restored": True, "sha256_matches": True,
        "size_matches": True, "inode_preserved": True,
        "project_sentinel_absent": True, "verified": True,
    }
    hosts.write_text("127.0.0.1 localhost\n127.0.0.77 settings.svc.halowaypoint.com\n")
    duplicate_state = tmp_path / "duplicate-prior.json"
    host_redirect.record_prior_state(duplicate_state, hosts)
    with pytest.raises(host_redirect.RedirectSafetyError, match="duplicate"):
        host_redirect.install_commands(host_redirect.AUTHORIZED_HOST,
                                       host_redirect.OBSERVER_LOOPBACK, hosts, duplicate_state)


def test_redirect_record_and_exact_line_rollback_contract(tmp_path: Path) -> None:
    hosts = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n192.0.2.1 synthetic.invalid\n"
    hosts.write_bytes(original)
    state, payload = tmp_path / "prior.json", tmp_path / "cleaned"
    record = host_redirect.record_prior_state(state, hosts)
    assert record["size"] == len(original)
    assert record["authorized_line"] == _authorized_hosts_line().decode().rstrip("\n")
    inode = hosts.stat().st_ino
    with hosts.open("ab") as stream:
        stream.write(_authorized_hosts_line())
    host_redirect.materialize_rollback(state, payload)
    assert payload.read_bytes() == original
    with hosts.open("wb") as stream:
        stream.write(payload.read_bytes())
    verified = host_redirect.verify_rollback(state, hosts)
    assert verified["verified"] and hosts.stat().st_ino == inode


@pytest.mark.parametrize("change", ["append", "edit", "duplicate", "missing"])
def test_redirect_rollback_refuses_ambiguous_or_concurrent_state(
    tmp_path: Path, change: str
) -> None:
    hosts = tmp_path / "hosts"
    original = b"127.0.0.1 localhost\n"
    hosts.write_bytes(original)
    state = tmp_path / "prior.json"
    record = host_redirect.record_prior_state(state, hosts)
    if change == "append":
        hosts.write_bytes(original + _authorized_hosts_line() + b"192.0.2.2 unrelated.invalid\n")
    elif change == "edit":
        hosts.write_bytes(b"127.0.0.2 localhost\n" + _authorized_hosts_line())
    elif change == "duplicate":
        hosts.write_bytes(original + _authorized_hosts_line() * 2)
    else:
        hosts.write_bytes(original)
    with pytest.raises(host_redirect.RedirectSafetyError, match="emergency command"):
        host_redirect.materialize_rollback(state, tmp_path / "must-not-exist")
    assert not (tmp_path / "must-not-exist").exists()
    emergency = host_redirect.emergency_rollback_command(record)
    assert "cleaned =" in emergency and "parts.count(line) != 1" in emergency


def test_local_ca_rejects_long_validity_repository_and_symlink_outputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="validity"):
        local_ca.generate(tmp_path / "long", days=3)
    repository_output = Path(__file__).resolve().parents[1] / "scratch-ca-must-not-exist"
    with pytest.raises(ValueError, match="outside the repository"):
        local_ca.generate(repository_output)
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        local_ca.generate(link)
    with pytest.raises(ValueError, match="production certificate host"):
        local_ca.generate(
            tmp_path / "wrong-host",
            constrain_to_host="gamecms-hacs.svc.halowaypoint.com",
        )
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "server.key").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(ValueError, match="already exist"):
        local_ca.generate(occupied)
    exact = tmp_path / "exact-production"
    local_ca.generate(
        exact, constrain_to_host=local_ca.AUTHORIZED_PRODUCTION_HOST, days=2
    )
    from cryptography import x509

    ca = x509.load_pem_x509_certificate((exact / "ca.crt").read_bytes())
    import datetime

    assert ca.not_valid_after_utc - ca.not_valid_before_utc <= datetime.timedelta(days=2)
    constraints = ca.extensions.get_extension_for_class(x509.NameConstraints)
    assert constraints.critical is True
    assert [name.value for name in constraints.value.excluded_subtrees] == [
        f".{local_ca.AUTHORIZED_PRODUCTION_HOST}"
    ]


def test_wine_install_fails_closed_unless_exact_thumbprint_is_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, days=1)
    calls = iter([
        SimpleNamespace(returncode=0, stdout="ok", stderr=""),
        SimpleNamespace(returncode=1, stdout="missing", stderr=""),
    ])
    monkeypatch.setattr(wine_trust, "_run_wine", lambda *_args, **_kwargs: next(calls))
    with pytest.raises(SystemExit, match="exact thumbprint"):
        wine_trust.install(cert_dir / "ca.crt", tmp_path, Path("wine"), tmp_path)


def test_wine_presence_requires_exact_key_and_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    thumbprint = "A" * 40
    exact = (
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\"
        f"{thumbprint}\n    Blob    REG_BINARY    00\n"
    )
    monkeypatch.setattr(
        wine_trust,
        "_run_wine",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=exact, stderr=""),
    )
    assert wine_trust.is_present(thumbprint, tmp_path, Path("wine")) is True
    monkeypatch.setattr(
        wine_trust,
        "_run_wine",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=f"Blob REG_BINARY {thumbprint}", stderr=""
        ),
    )
    assert wine_trust.is_present(thumbprint, tmp_path, Path("wine")) is False


@pytest.mark.parametrize("bad", [
    "A" * 39, "A" * 41, "AA:BB" + "A" * 35, " A" * 20,
    "A" * 39 + "\\", "A" * 39 + "/", "G" * 40,
])
def test_wine_thumbprint_validation_rejects_malformed_values(bad: str) -> None:
    with pytest.raises(ValueError, match="40 hexadecimal"):
        wine_trust.normalize_thumbprint(bad)


def test_wine_install_returns_required_verified_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, days=1)
    ca = x509.load_pem_x509_certificate((cert_dir / "ca.crt").read_bytes())
    tp = wine_trust.thumbprint(ca)
    query = (
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\SystemCertificates\\Root\\Certificates\\"
        f"{tp}\n    Blob    REG_BINARY    00\n"
    )
    calls = iter([
        SimpleNamespace(returncode=0, stdout="ok", stderr=""),
        SimpleNamespace(returncode=0, stdout=query, stderr=""),
    ])
    monkeypatch.setattr(wine_trust, "_run_wine", lambda *_args, **_kwargs: next(calls))
    result = wine_trust.install(cert_dir / "ca.crt", tmp_path, Path("wine"), tmp_path)
    assert result["verified_present"] is True


@pytest.mark.parametrize(
    ("delete", "query", "message"),
    [
        (SimpleNamespace(returncode=5, stdout="", stderr="failed"), None, "reg delete"),
        (
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(returncode=5, stdout="", stderr="query failed"),
            "query failed",
        ),
        (
            SimpleNamespace(returncode=0, stdout="", stderr=""),
            SimpleNamespace(
                returncode=0,
                stdout=(
                    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\SystemCertificates\\Root\\"
                    f"Certificates\\{'A' * 40}\n    Blob    REG_BINARY    00\n"
                ),
                stderr="",
            ),
            "remains",
        ),
    ],
)
def test_wine_remove_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, delete, query, message: str
) -> None:
    calls = iter([delete] if query is None else [delete, query])
    monkeypatch.setattr(wine_trust, "_run_wine", lambda *_args, **_kwargs: next(calls))
    with pytest.raises(SystemExit, match=message):
        wine_trust.remove("A" * 40, tmp_path, Path("wine"))


def test_wine_remove_requires_successful_exact_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = iter([
        SimpleNamespace(returncode=0, stdout="", stderr=""),
        SimpleNamespace(returncode=1, stdout="", stderr="unable to find registry key"),
    ])
    monkeypatch.setattr(wine_trust, "_run_wine", lambda *_args, **_kwargs: next(calls))
    result = wine_trust.remove("a" * 40, tmp_path, Path("wine"))
    assert result == {
        "action": "remove", "thumbprint_sha1": "A" * 40,
        "delete_exit_code": 0, "query_exit_code": 1,
        "query_status": "absent", "verified_absent": True,
    }


def test_request_target_and_dynamic_json_keys_are_value_free() -> None:
    target = schema_extract.normalize_request_target(
        "/users/1234567890/settings?token=SUPERSECRET&flight=private-value"
    )
    assert target == {
        "normalized_path": "/users/{id}/settings",
        "query_parameter_names": ["flight", "token"],
    }
    schema = schema_extract.extract_schema({
        "550e8400-e29b-41d4-a716-446655440000": {"enabled": True},
        "playerABC1234567890": {"enabled": False},
        "semanticName": "value",
    })
    blob = json.dumps(schema)
    assert "550e8400" not in blob
    assert "playerABC1234567890" not in blob
    assert "{dynamic_key_1}" in schema["properties"]
    assert "semanticName" in schema["properties"]
    opaque = "playerABC1234567890"
    normalized = schema_extract.normalize_request_target(f"/objects/{opaque}")
    assert normalized["normalized_path"] == "/objects/{id}"
    assert schema_extract.normalize_hostname(f"{opaque}.example.test") == "{id}.example.test"


@pytest.mark.parametrize("value", [
    "invented.person@invalid.test",
    "123e4567-e89b-12d3-a456-426614174000",
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJpbnZlbnRlZCJ9.signature",
    "XBL3.0 x=invented;tokenvalue",
    "76561190000000001", "2533274000000000",
    "abcdef0123456789abcdef0123456789",
    "QUFBQUFBQUFBQUFBQUFBQUFB",
    "QWxwaGEyX3N5bnRoZXRpYw",
    "abcdefghijklmnopqrstuvwx",
    "sessionAlphaBetaGamma123456789",
])
def test_request_target_adversarial_values_are_redacted_raw_and_encoded(value: str) -> None:
    encoded = "".join(f"%{byte:02X}" for byte in value.encode("utf-8"))
    for candidate in (value, encoded):
        result = schema_extract.normalize_request_target(
            f"/objects/{candidate}?token=discard-this#fragment-secret"
        )
        blob = json.dumps(result)
        assert result["query_parameter_names"] == ["token"]
        assert result["normalized_path"] in ("/objects/{id}", "/objects/{redacted_segment}")
        assert candidate not in blob and "discard-this" not in blob and "fragment-secret" not in blob


def test_origin_form_fragment_is_removed_before_path_processing() -> None:
    assert schema_extract.normalize_request_target("/safe/path#opaque-fragment") == {
        "normalized_path": "/safe/path", "query_parameter_names": [],
    }


def test_schema_redacts_all_adversarial_dynamic_keys_without_collisions() -> None:
    keys = [
        "QUFBQUFBQUFBQUFBQUFBQUFB",
        "abcdefghijklmnopqrstuvwx",
        "eyJhbGciOiJub25lIn0.eyJzdWIiOiJpbnZlbnRlZCJ9.signature",
        "123e4567%2De89b%2D12d3%2Da456%2D426614174000",
    ]
    schema = schema_extract.extract_schema(
        {key: {"representative": index} for index, key in enumerate(keys)}, "synthetic"
    )
    blob = json.dumps(schema, sort_keys=True)
    fixture_blob = json.dumps(schema_extract.synthesize(schema, "fixed"), sort_keys=True)
    assert schema["dynamic_key_count"] == len(keys)
    assert sorted(schema["properties"]) == [f"{{dynamic_key_{index}}}" for index in range(1, 5)]
    assert all(key not in blob and key not in fixture_blob for key in keys)
    assert schema_extract.synthesize(schema, "fixed") == schema_extract.synthesize(schema, "fixed")


def test_preflight_is_fail_closed_and_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, constrain_to_host=local_ca.AUTHORIZED_PRODUCTION_HOST, days=1)
    from cryptography import x509

    ca = x509.load_pem_x509_certificate((cert_dir / "ca.crt").read_bytes())
    thumbprint = wine_trust.thumbprint(ca)
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    (prefix / "system.reg").write_text("synthetic empty registry\n", encoding="utf-8")
    wine = tmp_path / "wine"
    wine.write_text("synthetic executable placeholder\n", encoding="utf-8")
    wine.chmod(0o700)
    values = {
        "branch": "main", "head": "a" * 40, "parent": "b" * 40,
        "remote_tip": "a" * 40, "status": "", "ahead_behind": "0\t0",
    }

    def command(args):
        key = {
            ("git", "branch", "--show-current"): "branch",
            ("git", "rev-parse", "HEAD"): "head",
            ("git", "rev-parse", "HEAD^"): "parent",
            ("git", "rev-parse", "origin/main"): "remote_tip",
            ("git", "status", "--porcelain", "--untracked-files=normal"): "status",
            ("git", "rev-list", "--left-right", "--count", "origin/main...HEAD"):
                "ahead_behind",
        }[tuple(args)]
        return SimpleNamespace(returncode=0, stdout=values[key] + "\n", stderr="")

    def resolve(host, family):
        suffix = host_redirect.IDENTITY_HOSTS.index(host) + 10 if host in host_redirect.IDENTITY_HOSTS else 9
        return [f"20.1.1.{suffix}"] if family == socket.AF_INET else []

    dependencies = {
        "command": command, "environment": {}, "listener_in_use": lambda *_: False,
        "processes": lambda: [], "resolve": resolve,
        "read_hosts": lambda: b"127.0.0.1 localhost\n",
        "tool_exists": lambda _name: True,
        "wine_presence": lambda *_args: {"status": "absent"},
    }
    before = sorted(str(path) for path in tmp_path.rglob("*"))
    result = p0c2d_preflight.run_preflight(
        stage="tls-observer", upstream_ip="20.184.144.194",
        cert_path=cert_dir / "server.crt", key_path=cert_dir / "server.key",
        pid_file=tmp_path / "run.pid", ready_file=tmp_path / "run.ready",
        log_path=tmp_path / "run.json", expected_branch="main",
        expected_head="a" * 40, expected_remote_tip="a" * 40,
        expected_parent="b" * 40, scratch_path=tmp_path,
        prefix=prefix, proton_wine=wine, ca_thumbprint=thumbprint,
        dependencies=dependencies,
    )
    after = sorted(str(path) for path in tmp_path.rglob("*"))
    assert result["pass"] is True
    assert before == after
    failed = p0c2d_preflight.run_preflight(
        stage="tls-observer", upstream_ip="127.0.0.1",
        cert_path=cert_dir / "server.crt", key_path=cert_dir / "server.key",
        pid_file=tmp_path / "run.pid", ready_file=tmp_path / "run.ready",
        log_path=tmp_path / "run.json", expected_branch="main",
        expected_head="a" * 40, expected_remote_tip="a" * 40,
        expected_parent="b" * 40, scratch_path=tmp_path,
        prefix=prefix, proton_wine=wine, ca_thumbprint=thumbprint,
        dependencies=dependencies,
    )
    assert failed["pass"] is False


def test_preflight_blocks_each_adversarial_gate(
    tmp_path: Path,
) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, constrain_to_host=local_ca.AUTHORIZED_PRODUCTION_HOST, days=1)
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    wine = tmp_path / "wine"
    wine.write_text("synthetic\n", encoding="utf-8")
    wine.chmod(0o700)
    ca = x509.load_pem_x509_certificate((cert_dir / "ca.crt").read_bytes())
    thumbprint = wine_trust.thumbprint(ca)
    git_values = {
        "branch": "main", "head": "a" * 40, "parent": "b" * 40,
        "remote": "a" * 40, "status": "", "ahead": "0\t0",
    }

    def command(args):
        mapping = {
            ("git", "branch", "--show-current"): "branch",
            ("git", "rev-parse", "HEAD"): "head",
            ("git", "rev-parse", "HEAD^"): "parent",
            ("git", "rev-parse", "origin/main"): "remote",
            ("git", "status", "--porcelain", "--untracked-files=normal"): "status",
            ("git", "rev-list", "--left-right", "--count", "origin/main...HEAD"): "ahead",
        }
        return SimpleNamespace(returncode=0, stdout=git_values[mapping[tuple(args)]] + "\n", stderr="")

    def safe_resolve(host, family):
        index = host_redirect.IDENTITY_HOSTS.index(host) + 20 if host in host_redirect.IDENTITY_HOSTS else 10
        return [f"20.2.2.{index}"] if family == socket.AF_INET else []

    base = {
        "command": command, "environment": {}, "listener_in_use": lambda *_: False,
        "processes": lambda: [], "resolve": safe_resolve,
        "read_hosts": lambda: b"127.0.0.1 localhost\n",
        "tool_exists": lambda _name: True,
        "wine_presence": lambda *_args: {"status": "absent"},
    }

    def run(overrides=None):
        deps = dict(base)
        deps.update(overrides or {})
        return p0c2d_preflight.run_preflight(
            stage="tls-observer", upstream_ip="20.184.144.194",
            cert_path=cert_dir / "server.crt", key_path=cert_dir / "server.key",
            pid_file=tmp_path / "out.pid", ready_file=tmp_path / "out.ready",
            log_path=tmp_path / "out.json", expected_branch="main",
            expected_head="a" * 40, expected_remote_tip="a" * 40,
            expected_parent="b" * 40, scratch_path=tmp_path,
            prefix=prefix, proton_wine=wine, ca_thumbprint=thumbprint,
            dependencies=deps,
        )

    assert run()["pass"] is True
    cases = [
        ({"environment": {"HTTPS_PROXY": "http://proxy.invalid"}}, "proxy_environment"),
        ({"listener_in_use": lambda *_: True}, "listener"),
        ({"processes": lambda: [(42, "python prelaunch_relay.py")]}, "processes"),
        ({"processes": lambda: [(43, "steam")]}, "processes"),
        ({"read_hosts": lambda: b"127.0.0.77 settings.svc.halowaypoint.com\n"}, "hosts"),
        ({"read_hosts": lambda: b"# P0C2D-REDIRECT\n"}, "hosts"),
        ({"resolve": lambda _host, family: ["127.0.0.1"] if family == socket.AF_INET else []},
         "identity_hosts"),
        ({"wine_presence": lambda *_args: {"status": "present"}}, "ca_absence"),
        ({"wine_presence": lambda *_args: {"status": "error"}}, "ca_absence"),
        ({"tool_exists": lambda _name: False}, "tools"),
    ]
    for overrides, failed_check in cases:
        result = run(overrides)
        assert result["pass"] is False
        assert result["checks"][failed_check]["pass"] is False

    git_values["status"] = "?? unexpected"
    result = run()
    assert result["checks"]["git"]["pass"] is False

    unsafe_path = p0c2d_preflight.run_preflight(
        stage="tls-observer", upstream_ip="20.184.144.194",
        cert_path=cert_dir / "server.crt", key_path=cert_dir / "server.key",
        pid_file=Path(__file__).resolve().parents[1] / "must-not-create.pid",
        ready_file=tmp_path / "out.ready", log_path=tmp_path / "out.json",
        expected_branch="main", expected_head="a" * 40, expected_remote_tip="a" * 40,
        expected_parent="b" * 40, scratch_path=Path(__file__).resolve().parents[1],
        prefix=prefix, proton_wine=wine, ca_thumbprint=thumbprint,
        dependencies=base,
    )
    assert unsafe_path["checks"]["paths"]["pass"] is False


def test_tls_observer_records_alpn_and_no_values(tmp_path: Path) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(
        cert_dir, constrain_to_host=local_ca.AUTHORIZED_PRODUCTION_HOST, days=1
    )
    port, ready = _free_port(), threading.Event()
    result: dict = {}

    def server() -> None:
        result["records"] = tls_observer.run_observer(
            cert_dir / "server.crt", cert_dir / "server.key", port, "127.0.0.1",
            max_connections=1, total_timeout=5, ready_event=ready,
            log_path=tmp_path / "tls.json",
            required_sni=local_ca.AUTHORIZED_PRODUCTION_HOST,
        )

    thread = threading.Thread(target=server)
    thread.start()
    assert ready.wait(2)
    context = ssl.create_default_context(cafile=str(cert_dir / "ca.crt"))
    context.set_alpn_protocols(["http/1.1"])
    with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
        with context.wrap_socket(
            raw, server_hostname=local_ca.AUTHORIZED_PRODUCTION_HOST
        ) as client:
            client.sendall(
                b"GET /objects/1234567890?token=TOPSECRET HTTP/1.1\r\n"
                b"Host: localhost\r\nAuthorization: SECRET-VALUE\r\n\r\n"
            )
    thread.join(5)
    assert not thread.is_alive()
    record = result["records"][0]
    assert record["alpn"] == "http/1.1"
    assert record["sni"] == local_ca.AUTHORIZED_PRODUCTION_HOST
    assert record["normalized_path"] == "/objects/{id}"
    assert record["query_parameter_names"] == ["token"]
    assert record["request_header_names"] == ["authorization", "host"]
    assert record["certificate_verdict"] == "accepted_certificate"
    assert record["sni_result"] == "exact"
    assert "TOPSECRET" not in json.dumps(record) and "SECRET-VALUE" not in json.dumps(record)
    assert "TOPSECRET" not in (tmp_path / "tls.json").read_text(encoding="utf-8")


def test_production_observer_rejects_a_synthetic_certificate_before_bind(tmp_path: Path) -> None:
    cert_dir = tmp_path / "synthetic-certs"
    local_ca.generate(cert_dir, hostname="localhost", days=1)
    with pytest.raises(ValueError, match="exact-host"):
        tls_observer.run_observer(
            cert_dir / "server.crt",
            cert_dir / "server.key",
            port=443,
            bind="127.0.0.77",
            total_timeout=1,
            enforce_production=True,
        )


def test_tls_observer_bounds_a_stalled_handshake(tmp_path: Path) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, hostname="localhost", days=1)
    port, ready = _free_port(), threading.Event()
    result: dict = {}

    def server() -> None:
        started = time.monotonic()
        result["records"] = tls_observer.run_observer(
            cert_dir / "server.crt",
            cert_dir / "server.key",
            port,
            "127.0.0.1",
            max_connections=1,
            total_timeout=0.4,
            ready_event=ready,
        )
        result["elapsed"] = time.monotonic() - started

    thread = threading.Thread(target=server)
    thread.start()
    assert ready.wait(2)
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    thread.join(2)
    client.close()
    assert not thread.is_alive()
    assert result["elapsed"] < 1.0
    assert result["records"][0]["alert_class"] == "TimeoutError"


def _observe_one_tls_client(tmp_path: Path, *, server_hostname: str | None,
                            alpn: str = "http/1.1", send: bytes | None = None) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, hostname="p0c2a.test", days=1)
    port, ready = _free_port(), threading.Event()
    result = {}

    def server() -> None:
        result["records"] = tls_observer.run_observer(
            cert_dir / "server.crt", cert_dir / "server.key", port, "127.0.0.1",
            max_connections=1, total_timeout=3, ready_event=ready,
            required_sni="p0c2a.test",
        )

    thread = threading.Thread(target=server)
    thread.start()
    assert ready.wait(2)
    context = ssl.create_default_context(cafile=str(cert_dir / "ca.crt"))
    context.check_hostname = False
    context.set_alpn_protocols([alpn])
    with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
        with context.wrap_socket(raw, server_hostname=server_hostname) as client:
            if send:
                try:
                    client.sendall(send)
                except OSError:
                    pass
    thread.join(4)
    assert not thread.is_alive()
    return result["records"][0]


def test_tls_observer_exact_wrong_and_missing_sni(tmp_path: Path) -> None:
    exact = _observe_one_tls_client(
        tmp_path / "exact", server_hostname="p0c2a.test",
        send=b"GET /safe HTTP/1.1\r\nHost: p0c2a.test\r\n\r\n",
    )
    assert exact["sni_result"] == "exact"
    assert exact["certificate_verdict"] == "accepted_certificate"

    wrong = _observe_one_tls_client(
        tmp_path / "wrong", server_hostname="sibling.p0c2a.test",
        send=b"GET /must-not-parse HTTP/1.1\r\n\r\n",
    )
    assert wrong["sni_result"] == "mismatch"
    assert wrong["protocol_result"] == "sni_rejected"
    assert wrong["client_sent_application_data"] is False
    assert wrong["normalized_path"] is None

    missing = _observe_one_tls_client(
        tmp_path / "missing", server_hostname=None,
        send=b"GET /must-not-parse HTTP/1.1\r\n\r\n",
    )
    assert missing["sni_result"] == "missing"
    assert missing["protocol_result"] == "sni_rejected"
    assert missing["client_sent_application_data"] is False


def test_tls_observer_h2_is_explicitly_unsupported_and_unparsed(tmp_path: Path) -> None:
    record = _observe_one_tls_client(
        tmp_path, server_hostname="p0c2a.test", alpn="h2",
        send=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    )
    assert record["alpn"] == "h2"
    assert record["protocol_result"] == "unsupported_protocol"
    assert record["client_sent_application_data"] is True
    assert record["request_method"] is None and record["normalized_path"] is None
    assert record["certificate_verdict"] == "accepted_certificate"


def test_tls_observer_requires_application_data_for_acceptance(tmp_path: Path) -> None:
    record = _observe_one_tls_client(tmp_path, server_hostname="p0c2a.test", send=None)
    assert record["tls_completed"] is True
    assert record["client_sent_application_data"] is False
    assert record["certificate_verdict"] == "unknown_no_application_data"


def test_tls_observer_stale_control_and_bind_failure_lifecycle(tmp_path: Path) -> None:
    stale = tmp_path / "stale.ready"
    _write_control(stale, tls_observer.TLS_TOOL, "ready", 999_999_999)
    prelaunch_relay.prepare_control_path(stale, tls_observer.TLS_TOOL, "ready")
    assert not stale.exists()

    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, hostname="localhost", days=1)
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        port = occupied.getsockname()[1]
        artifacts = [tmp_path / "tls.json", tmp_path / "tls.pid", tmp_path / "tls.ready"]
        with pytest.raises(ValueError, match="already in use"):
            tls_observer.run_observer(
                cert_dir / "server.crt", cert_dir / "server.key", port, "127.0.0.1",
                total_timeout=0.5, log_path=artifacts[0], pid_file=artifacts[1],
                ready_file=artifacts[2],
            )
    assert not any(path.exists() for path in artifacts)


def test_reverse_proxy_fails_closed_as_not_ready() -> None:
    assert reverse_proxy.readiness()["status"] == "NOT READY"
    assert reverse_proxy.readiness()["network_path_present"] is False
    with pytest.raises(reverse_proxy.PassthroughNotReady):
        reverse_proxy.serve()


# --------------------------------------------------------------------------
# P0-C2D0-R2: live-preflight contract corrections
# --------------------------------------------------------------------------


def _git_command(values: dict, remote_ref: str = "origin/main"):
    """Strict mock: an unexpected Git query raises rather than silently passing."""
    mapping = {
        ("git", "branch", "--show-current"): "branch",
        ("git", "rev-parse", "HEAD"): "head",
        ("git", "rev-parse", "HEAD^"): "parent",
        ("git", "rev-parse", remote_ref): "remote_tip",
        ("git", "status", "--porcelain", "--untracked-files=normal"): "status",
        ("git", "rev-list", "--left-right", "--count", f"{remote_ref}...HEAD"): "ahead_behind",
    }

    def command(args):
        return SimpleNamespace(
            returncode=0, stdout=values[mapping[tuple(args)]] + "\n", stderr=""
        )

    return command


def _safe_preflight_dependencies(command) -> dict:
    def resolve(host, family):
        index = (
            host_redirect.IDENTITY_HOSTS.index(host) + 20
            if host in host_redirect.IDENTITY_HOSTS else 10
        )
        return [f"20.3.3.{index}"] if family == socket.AF_INET else []

    return {
        "command": command, "environment": {}, "listener_in_use": lambda *_: False,
        "processes": lambda: [], "resolve": resolve,
        "read_hosts": lambda: b"127.0.0.1 localhost\n",
        "tool_exists": lambda _name: True,
        "wine_presence": lambda *_args: {"status": "absent"},
    }


def _blind_relay_preflight(tmp_path: Path, values: dict, **overrides) -> dict:
    arguments = {
        "stage": "blind-relay",
        "upstream_ip": "20.184.144.194",
        "pid_file": tmp_path / "relay.pid",
        "ready_file": tmp_path / "relay.ready",
        "log_path": tmp_path / "relay.json",
        "expected_branch": "main",
        "expected_head": "a" * 40,
        "expected_remote_tip": "a" * 40,
        "expected_ahead": 0,
        "expected_behind": 0,
        "scratch_path": tmp_path,
        "dependencies": _safe_preflight_dependencies(_git_command(values)),
    }
    arguments.update(overrides)
    return p0c2d_preflight.run_preflight(**arguments)


def _synchronized_git_values() -> dict:
    return {
        "branch": "main", "head": "a" * 40, "parent": "b" * 40,
        "remote_tip": "a" * 40, "status": "", "ahead_behind": "0\t0",
    }


def test_preflight_accepts_the_pushed_synchronized_zero_zero_state(tmp_path: Path) -> None:
    """The authorized live state is HEAD == origin/main, which R1 could not express."""
    result = _blind_relay_preflight(tmp_path, _synchronized_git_values())
    assert result["pass"] is True
    assert result["checks"]["git"]["pass"] is True
    assert result["checks"]["git"]["actual"]["ahead"] == 0
    assert result["checks"]["git"]["actual"]["behind"] == 0
    assert result["checks"]["git"]["expected"]["ahead"] == 0
    assert result["checks"]["git"]["expected"]["behind"] == 0


def test_preflight_accepts_one_ahead_only_when_explicitly_expected(tmp_path: Path) -> None:
    values = _synchronized_git_values()
    values["remote_tip"] = "b" * 40
    values["ahead_behind"] = "0\t1"

    expected_one_ahead = _blind_relay_preflight(
        tmp_path, values, expected_remote_tip="b" * 40, expected_ahead=1,
    )
    assert expected_one_ahead["pass"] is True
    assert expected_one_ahead["checks"]["git"]["actual"]["ahead"] == 1

    unexpected = _blind_relay_preflight(tmp_path, values, expected_remote_tip="b" * 40)
    assert unexpected["checks"]["git"]["pass"] is False
    assert unexpected["checks"]["git"]["matches"]["ahead"] is False
    assert unexpected["checks"]["git"]["actual"]["ahead"] == 1
    assert unexpected["checks"]["git"]["expected"]["ahead"] == 0


def test_preflight_reports_unexpected_behind_state(tmp_path: Path) -> None:
    values = _synchronized_git_values()
    values["ahead_behind"] = "3\t0"
    result = _blind_relay_preflight(tmp_path, values)
    assert result["checks"]["git"]["pass"] is False
    assert result["checks"]["git"]["matches"]["behind"] is False
    assert result["checks"]["git"]["actual"]["behind"] == 3
    assert result["checks"]["git"]["matches"]["ahead"] is True


@pytest.mark.parametrize("malformed", ["", "0", "0\t1\t2", "x\ty", "-1\t0", "0 1 2"])
def test_preflight_fails_closed_on_malformed_rev_list_output(
    tmp_path: Path, malformed: str
) -> None:
    values = _synchronized_git_values()
    values["ahead_behind"] = malformed
    result = _blind_relay_preflight(tmp_path, values)
    assert result["checks"]["git"]["pass"] is False
    assert "ahead_behind_malformed" in result["checks"]["git"]["errors"]
    assert result["checks"]["git"]["actual"]["ahead"] is None
    assert result["checks"]["git"]["actual"]["behind"] is None


def test_preflight_fails_closed_when_a_git_query_fails(tmp_path: Path) -> None:
    def failing(_args):
        return SimpleNamespace(returncode=128, stdout="", stderr="fatal: synthetic")

    result = _blind_relay_preflight(
        tmp_path, _synchronized_git_values(),
        dependencies=_safe_preflight_dependencies(failing),
    )
    assert result["checks"]["git"]["pass"] is False
    assert result["checks"]["git"]["errors"]


def test_preflight_fails_closed_when_git_raises(tmp_path: Path) -> None:
    def raising(_args):
        raise OSError("synthetic git failure")

    result = _blind_relay_preflight(
        tmp_path, _synchronized_git_values(),
        dependencies=_safe_preflight_dependencies(raising),
    )
    assert result["checks"]["git"]["pass"] is False
    assert result["checks"]["git"]["errors"]


@pytest.mark.parametrize(
    ("field", "override"),
    [
        ("branch", {"expected_branch": "other"}),
        ("head", {"expected_head": "c" * 40}),
        ("remote_tip", {"expected_remote_tip": "d" * 40}),
    ],
)
def test_preflight_reports_identity_mismatches(
    tmp_path: Path, field: str, override: dict
) -> None:
    result = _blind_relay_preflight(tmp_path, _synchronized_git_values(), **override)
    assert result["checks"]["git"]["pass"] is False
    assert result["checks"]["git"]["matches"][field] is False


def test_preflight_parent_is_optional_and_checked_only_when_supplied(tmp_path: Path) -> None:
    values = _synchronized_git_values()
    without_parent = _blind_relay_preflight(tmp_path, values)
    assert "parent" not in without_parent["checks"]["git"]["matches"]

    with_parent = _blind_relay_preflight(tmp_path, values, expected_parent="b" * 40)
    assert with_parent["checks"]["git"]["matches"]["parent"] is True

    wrong_parent = _blind_relay_preflight(tmp_path, values, expected_parent="e" * 40)
    assert wrong_parent["checks"]["git"]["matches"]["parent"] is False


def test_preflight_hardcodes_no_commit_hash() -> None:
    source = (
        Path(p0c2d_preflight.__file__).read_text(encoding="utf-8")
    )
    import re

    assert not re.search(r"\b[0-9a-f]{40}\b", source)
    assert '"0\\t1"' not in source and "'0\\t1'" not in source


def test_blind_relay_stage_passes_with_no_certificate_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The blind relay terminates nothing, so no CA path may even be consulted."""
    def forbidden_certificate_check(*_args, **_kwargs):
        raise AssertionError("certificate check must not run in the blind-relay stage")

    def forbidden_wine(*_args, **_kwargs):
        raise AssertionError("Wine must not be inspected in the blind-relay stage")

    monkeypatch.setattr(p0c2d_preflight, "_certificate_check", forbidden_certificate_check)
    dependencies = _safe_preflight_dependencies(_git_command(_synchronized_git_values()))
    dependencies["wine_presence"] = forbidden_wine

    before = sorted(str(path) for path in tmp_path.rglob("*"))
    result = _blind_relay_preflight(
        tmp_path, _synchronized_git_values(), dependencies=dependencies
    )
    after = sorted(str(path) for path in tmp_path.rglob("*"))

    assert result["pass"] is True
    assert result["stage"] == "blind-relay"
    assert result["checks"]["certificate"] == {
        "pass": True, "status": "not_applicable_blind_relay"
    }
    assert result["checks"]["ca_absence"] == {
        "pass": True, "status": "not_applicable_blind_relay"
    }
    assert result["checks"]["stage"]["certificate_material_required"] is False
    assert before == after


@pytest.mark.parametrize(
    "unexpected",
    [
        {"cert_path": Path("/nonexistent/server.crt")},
        {"key_path": Path("/nonexistent/server.key")},
        {"prefix": Path("/nonexistent/prefix")},
        {"proton_wine": Path("/nonexistent/wine")},
        {"ca_thumbprint": "A" * 40},
    ],
)
def test_blind_relay_stage_rejects_unexpected_certificate_arguments(
    tmp_path: Path, unexpected: dict
) -> None:
    result = _blind_relay_preflight(tmp_path, _synchronized_git_values(), **unexpected)
    assert result["pass"] is False
    assert result["checks"]["stage"]["pass"] is False
    assert result["checks"]["stage"]["unexpected_arguments"]


def test_tls_observer_stage_requires_its_certificate_inputs(tmp_path: Path) -> None:
    result = p0c2d_preflight.run_preflight(
        stage="tls-observer", upstream_ip="20.184.144.194",
        pid_file=tmp_path / "obs.pid", ready_file=tmp_path / "obs.ready",
        log_path=tmp_path / "obs.json", expected_branch="main",
        expected_head="a" * 40, expected_remote_tip="a" * 40,
        scratch_path=tmp_path,
        dependencies=_safe_preflight_dependencies(_git_command(_synchronized_git_values())),
    )
    assert result["pass"] is False
    assert result["checks"]["stage"]["pass"] is False
    assert result["checks"]["stage"]["missing_arguments"] == ["cert", "key"]
    assert result["checks"]["certificate"]["reason"] == "missing_certificate_inputs"


def test_preflight_stage_is_never_inferred(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="never inferred"):
        _blind_relay_preflight(tmp_path, _synchronized_git_values(), stage="whatever")


# --- upstream TLS probe ----------------------------------------------------


@pytest.mark.parametrize(
    "rejected",
    [
        "settings.svc.halowaypoint.com", "localhost", "", "   ", "20.184.144.194:443",
        "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1",
        "224.0.0.1", "239.255.255.250", "233.252.0.1", "0.0.0.0", "255.255.255.255",
        "240.0.0.1", "100.64.0.1", "192.0.2.1", "198.51.100.5", "203.0.113.9",
        "198.18.0.1", "2606:4700::1111", "::1", "not-an-address",
    ],
)
def test_upstream_probe_rejects_every_unauthorized_candidate(rejected: str) -> None:
    with pytest.raises(upstream_probe.UpstreamProbeError):
        upstream_probe.classify_candidate_ip(rejected)
    with pytest.raises(upstream_probe.UpstreamProbeError):
        upstream_probe.probe(rejected)


def test_upstream_probe_accepts_a_global_unicast_candidate_without_connecting() -> None:
    address = upstream_probe.classify_candidate_ip("20.184.144.194")
    assert str(address) == "20.184.144.194"
    assert upstream_probe.validate_production_target(
        "SETTINGS.SVC.HALOWAYPOINT.COM.", "20.184.144.194", 443
    ) == address


def test_upstream_probe_rejects_a_wrong_hostname_or_port() -> None:
    with pytest.raises(upstream_probe.UpstreamProbeError, match="hostname"):
        upstream_probe.validate_production_target(
            "gamecms-hacs.svc.halowaypoint.com", "20.184.144.194", 443
        )
    with pytest.raises(upstream_probe.UpstreamProbeError, match="port"):
        upstream_probe.validate_production_target(
            upstream_probe.AUTHORIZED_HOST, "20.184.144.194", 8443
        )


def test_upstream_probe_synthetic_entry_point_cannot_reach_production() -> None:
    with pytest.raises(upstream_probe.UpstreamProbeError, match="loopback-only"):
        upstream_probe.synthetic_probe("20.184.144.194", 8443, "x.invalid", Path("/dev/null"))
    with pytest.raises(upstream_probe.UpstreamProbeError, match="high unprivileged"):
        upstream_probe.synthetic_probe("127.0.0.1", 443, "x.invalid", Path("/dev/null"))
    with pytest.raises(upstream_probe.UpstreamProbeError, match="production hostname"):
        upstream_probe.synthetic_probe(
            "127.0.0.1", 8443, upstream_probe.AUTHORIZED_HOST, Path("/dev/null")
        )


class _SyntheticTlsServer:
    """One-shot loopback TLS server that records whether the client sent data."""

    def __init__(self, cert_dir: Path, alpn: list[str] | None = None):
        self.port = _free_port()
        self.application_bytes = None
        self.ready = threading.Event()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_dir / "server.crt", cert_dir / "server.key")
        if alpn:
            context.set_alpn_protocols(alpn)
        self._context = context
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", self.port))
            listener.listen(1)
            listener.settimeout(5)
            self.ready.set()
            try:
                raw, _ = listener.accept()
            except (TimeoutError, OSError):
                return
            try:
                with self._context.wrap_socket(raw, server_side=True) as tls:
                    tls.settimeout(2)
                    try:
                        self.application_bytes = tls.recv(4096)
                    except (OSError, ssl.SSLError):
                        self.application_bytes = b""
            except (OSError, ssl.SSLError):
                raw.close()

    def __enter__(self) -> _SyntheticTlsServer:
        self._thread.start()
        assert self.ready.wait(3)
        return self

    def __exit__(self, *_exc) -> None:
        self._thread.join(6)
        assert not self._thread.is_alive()


def test_upstream_probe_collects_metadata_and_sends_no_application_data(
    tmp_path: Path,
) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(
        cert_dir, hostname="settings-test.invalid", days=1, name_constraints=False
    )
    with _SyntheticTlsServer(cert_dir, alpn=["http/1.1"]) as server:
        record = upstream_probe.synthetic_probe(
            "127.0.0.1", server.port, "settings-test.invalid", cert_dir / "ca.crt"
        )

    assert record["verified"] is True
    assert record["tls_completed"] is True
    assert record["error_class"] is None
    assert record["sni"] == "settings-test.invalid"
    assert record["hostname_verification"] is True
    assert record["verify_mode"] == "CERT_REQUIRED"
    assert record["advertised_alpn"] == ["h2", "http/1.1"]
    assert record["negotiated_alpn"] == "http/1.1"
    assert record["tls_version"].startswith("TLSv1.")
    assert record["cipher_name"] and isinstance(record["cipher_bits"], int)
    assert record["certificate_subject"] == "CN=settings-test.invalid"
    assert "P0-C2A Local Test CA" in record["certificate_issuer"]
    assert len(record["certificate_sha256_fingerprint"].split(":")) == 32
    assert record["application_bytes_sent"] == 0
    assert record["http_request_sent"] is False
    # The server side is the authority on whether a byte was written: it
    # completed the handshake and then read end-of-stream, not a request.
    assert server.application_bytes == b""


def test_upstream_probe_metadata_contains_no_certificate_body(tmp_path: Path) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(
        cert_dir, hostname="settings-test.invalid", days=1, name_constraints=False
    )
    with _SyntheticTlsServer(cert_dir) as server:
        record = upstream_probe.synthetic_probe(
            "127.0.0.1", server.port, "settings-test.invalid", cert_dir / "ca.crt"
        )
    blob = json.dumps(record)
    assert "BEGIN CERTIFICATE" not in blob and "MII" not in blob
    pem = (cert_dir / "server.crt").read_text(encoding="utf-8")
    body = "".join(pem.splitlines()[1:-1])
    assert body[:32] not in blob


def test_upstream_probe_rejects_an_untrusted_certificate(tmp_path: Path) -> None:
    cert_dir = tmp_path / "certs"
    other_ca = tmp_path / "other"
    local_ca.generate(
        cert_dir, hostname="settings-test.invalid", days=1, name_constraints=False
    )
    local_ca.generate(
        other_ca, hostname="unrelated.invalid", days=1, name_constraints=False
    )
    with _SyntheticTlsServer(cert_dir) as server:
        record = upstream_probe.synthetic_probe(
            "127.0.0.1", server.port, "settings-test.invalid", other_ca / "ca.crt"
        )
    assert record["verified"] is False
    assert record["error_class"] == "SSLCertVerificationError"
    assert record["certificate_sha256_fingerprint"] is None


def test_upstream_probe_rejects_a_hostname_mismatch(tmp_path: Path) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(
        cert_dir, hostname="settings-test.invalid", days=1, name_constraints=False
    )
    with _SyntheticTlsServer(cert_dir) as server:
        record = upstream_probe.synthetic_probe(
            "127.0.0.1", server.port, "different-name.invalid", cert_dir / "ca.crt"
        )
    assert record["verified"] is False
    assert record["error_class"] == "SSLCertVerificationError"
    assert "hostname mismatch" in (record["error_detail"] or "").lower()


def test_upstream_probe_records_a_refused_connection_without_raising(tmp_path: Path) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(
        cert_dir, hostname="settings-test.invalid", days=1, name_constraints=False
    )
    record = upstream_probe.synthetic_probe(
        "127.0.0.1", _free_port(), "settings-test.invalid", cert_dir / "ca.crt", timeout=2.0
    )
    assert record["verified"] is False
    assert record["tls_completed"] is False
    assert record["error_class"] == "ConnectionRefusedError"


def test_upstream_probe_leaves_no_listener_behind(tmp_path: Path) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(
        cert_dir, hostname="settings-test.invalid", days=1, name_constraints=False
    )
    with _SyntheticTlsServer(cert_dir) as server:
        port = server.port
        upstream_probe.synthetic_probe(
            "127.0.0.1", port, "settings-test.invalid", cert_dir / "ca.crt"
        )
    with socket.socket() as probe_socket:
        probe_socket.settimeout(1)
        assert probe_socket.connect_ex(("127.0.0.1", port)) != 0


# --- relay live bounds -----------------------------------------------------


def test_relay_recommended_live_bounds_are_internally_consistent() -> None:
    total = prelaunch_relay.RECOMMENDED_LIVE_SECONDS
    idle = prelaunch_relay.RECOMMENDED_LIVE_IDLE_SECONDS
    observed = prelaunch_relay.OBSERVED_LAUNCH_TO_TITLE_SERVICE_SECONDS
    # The hard maximum is unchanged; the recommendation lives inside it.
    assert prelaunch_relay.MAX_SECONDS == 300.0
    assert total <= prelaunch_relay.MAX_SECONDS
    # Enough margin over the measured launch-to-title-service delay to cover
    # Steam startup and operator latency.
    assert total >= observed * 2
    # A quiet but healthy settings connection must not be torn down early.
    assert idle >= total
    assert prelaunch_relay.RECOMMENDED_LIVE_MAX_CONNECTIONS > 1
    assert prelaunch_relay.RECOMMENDED_LIVE_MAX_CONNECTIONS <= prelaunch_relay.MAX_CONNECTIONS
    prelaunch_relay.validate_bounds(
        prelaunch_relay.RECOMMENDED_LIVE_MAX_CONNECTIONS, total, idle
    )


def test_relay_does_not_exit_after_first_connection_while_lingering(tmp_path: Path) -> None:
    """A completed connection must not end the run while a redirect is installed."""
    upstream_port, relay_port = _free_port(), _free_port()
    upstream_ready = threading.Event()

    def upstream() -> None:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", upstream_port))
            listener.listen(2)
            listener.settimeout(4)
            upstream_ready.set()
            for _ in range(2):
                try:
                    conn, _ = listener.accept()
                except (TimeoutError, OSError):
                    return
                with conn:
                    while conn.recv(1024):
                        pass

    upstream_thread = threading.Thread(target=upstream, daemon=True)
    upstream_thread.start()
    assert upstream_ready.wait(2)

    ready = threading.Event()
    result: dict = {}

    def relay() -> None:
        result["state"] = prelaunch_relay.serve(
            "127.0.0.1", relay_port, "synthetic.test", "127.0.0.1", upstream_port,
            tmp_path / "linger.json", 2, 2.5, 2.5,
            enforce_production=False, ready_event=ready, linger_until_deadline=True,
        )

    relay_thread = threading.Thread(target=relay, daemon=True)
    relay_thread.start()
    assert ready.wait(2)

    with socket.create_connection(("127.0.0.1", relay_port), timeout=2) as first:
        first.sendall(b"first")
    time.sleep(0.4)
    # The relay is still listening after the first connection finished.
    assert relay_thread.is_alive()
    with socket.create_connection(("127.0.0.1", relay_port), timeout=2) as second:
        second.sendall(b"second")

    relay_thread.join(5)
    assert not relay_thread.is_alive()
    state = result["state"]
    assert len(state.connections) == 2
    assert state.exit_reason in {"total_deadline", "connection_cap_reached_lingering"}


def test_relay_records_over_cap_connections_instead_of_exiting(tmp_path: Path) -> None:
    upstream_port, relay_port = _free_port(), _free_port()
    upstream_ready = threading.Event()

    def upstream() -> None:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", upstream_port))
            listener.listen(1)
            listener.settimeout(4)
            upstream_ready.set()
            try:
                conn, _ = listener.accept()
            except (TimeoutError, OSError):
                return
            with conn:
                while conn.recv(1024):
                    pass

    upstream_thread = threading.Thread(target=upstream, daemon=True)
    upstream_thread.start()
    assert upstream_ready.wait(2)

    ready = threading.Event()
    result: dict = {}

    def relay() -> None:
        result["state"] = prelaunch_relay.serve(
            "127.0.0.1", relay_port, "synthetic.test", "127.0.0.1", upstream_port,
            tmp_path / "cap.json", 1, 2.0, 2.0,
            enforce_production=False, ready_event=ready, linger_until_deadline=True,
        )

    relay_thread = threading.Thread(target=relay, daemon=True)
    relay_thread.start()
    assert ready.wait(2)

    with socket.create_connection(("127.0.0.1", relay_port), timeout=2) as first:
        first.sendall(b"capped")
        time.sleep(0.3)
        # Cap already reached: the next connection is closed and recorded, and
        # the relay stays up rather than leaving the redirect pointing nowhere.
        with socket.create_connection(("127.0.0.1", relay_port), timeout=2):
            pass
        assert relay_thread.is_alive()

    relay_thread.join(5)
    assert not relay_thread.is_alive()
    state = result["state"]
    classes = [entry["error_class"] for entry in state.connections]
    assert "ConnectionCapReached" in classes
    assert state.exit_reason == "connection_cap_reached_lingering"
    persisted = json.loads((tmp_path / "cap.json").read_text(encoding="utf-8"))
    assert persisted["exit_reason"] == "connection_cap_reached_lingering"
    assert "capped" not in json.dumps(persisted)


def test_relay_exit_reason_is_recorded_for_a_deadline_run(tmp_path: Path) -> None:
    relay_port, upstream_port = _free_port(), _free_port()
    state = prelaunch_relay.serve(
        "127.0.0.1", relay_port, "synthetic.test", "127.0.0.1", upstream_port,
        tmp_path / "deadline-reason.json", 1, 0.4, 0.4, enforce_production=False,
    )
    assert state.exit_reason == "total_deadline"
    persisted = json.loads((tmp_path / "deadline-reason.json").read_text(encoding="utf-8"))
    assert persisted["exit_reason"] == "total_deadline"
    assert persisted["connection_count"] == 0


@pytest.mark.parametrize(
    "rejected",
    ["224.0.0.1", "239.255.255.250", "255.255.255.255", "240.0.0.1", "0.0.0.0", "100.64.0.1"],
)
def test_relay_production_contract_rejects_non_unicast_upstreams(rejected: str) -> None:
    """`is_global` alone lets IPv4 multicast through; each class is rejected explicitly."""
    with pytest.raises(prelaunch_relay.RelaySafetyError):
        prelaunch_relay.validate_production_contract(
            prelaunch_relay.AUTHORIZED_BIND, prelaunch_relay.AUTHORIZED_HOST, rejected, 443
        )


# --------------------------------------------------------------------------
# P0-C2D1-R0: TLS observer live-bounds correction
# --------------------------------------------------------------------------


def test_observer_live_bounds_are_internally_consistent() -> None:
    total = tls_observer.RECOMMENDED_LIVE_SECONDS
    # One hard runtime bound across the live interception tools, so the observer
    # cannot silently diverge from the relay again.
    assert tls_observer.MAX_SECONDS == prelaunch_relay.MAX_SECONDS
    assert total <= tls_observer.MAX_SECONDS
    assert 1 < tls_observer.RECOMMENDED_LIVE_MAX_CONNECTIONS <= tls_observer.MAX_CONNECTIONS


def test_observer_runtime_covers_the_measured_live_timeline() -> None:
    """The regression that would have caught the superseded 120s cap.

    The observer starts before the redirect is installed, so its runtime has to
    cover the whole measured redirect-verify-to-connect interval with margin for
    the install and scope verification that precede it.
    """
    total = tls_observer.RECOMMENDED_LIVE_SECONDS
    measured = tls_observer.OBSERVED_REDIRECT_VERIFY_TO_CONNECT_SECONDS
    assert measured >= tls_observer.OBSERVED_LAUNCH_TO_TITLE_SERVICE_SECONDS
    assert total >= measured * 2
    # The superseded cap could not express this bound at all.
    assert measured * 2 > 120.0


def test_observer_accepts_the_recommended_live_runtime(tmp_path: Path) -> None:
    """Previously this raised: 240s exceeded the superseded 120s maximum."""
    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, hostname="p0c2a.test", days=1)
    port, ready = _free_port(), threading.Event()
    result: dict = {}

    def server() -> None:
        result["records"] = tls_observer.run_observer(
            cert_dir / "server.crt", cert_dir / "server.key", port, "127.0.0.1",
            max_connections=1, total_timeout=tls_observer.RECOMMENDED_LIVE_SECONDS,
            ready_event=ready, required_sni="p0c2a.test",
        )

    thread = threading.Thread(target=server)
    thread.start()
    # Reaching ready proves the 240s bound was accepted and the listener bound.
    assert ready.wait(5)
    # One connection then retires the run at its cap, so the test does not wait
    # out the full recommended runtime or leave a listener behind.
    context = ssl.create_default_context(cafile=str(cert_dir / "ca.crt"))
    with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
        with context.wrap_socket(raw, server_hostname="p0c2a.test") as client:
            client.sendall(b"GET /safe HTTP/1.1\r\nHost: p0c2a.test\r\n\r\n")
    thread.join(10)
    assert not thread.is_alive()
    assert result["records"][0]["sni_result"] == "exact"


def test_observer_rejects_runtime_above_the_hard_maximum(tmp_path: Path) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, hostname="localhost", days=1)
    with pytest.raises(ValueError, match="total_timeout"):
        tls_observer.run_observer(
            cert_dir / "server.crt", cert_dir / "server.key", _free_port(), "127.0.0.1",
            total_timeout=tls_observer.MAX_SECONDS + 1,
        )


def test_observer_records_a_deadline_exit_with_no_observation(tmp_path: Path) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, hostname="localhost", days=1)
    log = tmp_path / "deadline.json"
    records = tls_observer.run_observer(
        cert_dir / "server.crt", cert_dir / "server.key", _free_port(), "127.0.0.1",
        max_connections=1, total_timeout=0.4, log_path=log,
    )
    assert records == []
    persisted = json.loads(log.read_text(encoding="utf-8"))
    assert persisted["format"] == tls_observer.LOG_FORMAT
    assert persisted["exit_reason"] == "total_deadline"
    assert persisted["observation_count"] == 0
    assert persisted["total_timeout_seconds"] == 0.4
    assert persisted["elapsed_seconds"] >= 0.4


def test_observer_records_a_cap_exit_distinctly(tmp_path: Path) -> None:
    """A cap-bounded run must never read as a run that reached its deadline."""
    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, hostname="p0c2a.test", days=1)
    port, ready = _free_port(), threading.Event()
    log = tmp_path / "cap.json"

    def server() -> None:
        tls_observer.run_observer(
            cert_dir / "server.crt", cert_dir / "server.key", port, "127.0.0.1",
            max_connections=1, total_timeout=10, ready_event=ready, log_path=log,
            required_sni="p0c2a.test",
        )

    thread = threading.Thread(target=server)
    thread.start()
    assert ready.wait(2)
    context = ssl.create_default_context(cafile=str(cert_dir / "ca.crt"))
    with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
        with context.wrap_socket(raw, server_hostname="p0c2a.test") as client:
            client.sendall(b"GET /safe HTTP/1.1\r\nHost: p0c2a.test\r\n\r\n")
    thread.join(5)
    assert not thread.is_alive()
    persisted = json.loads(log.read_text(encoding="utf-8"))
    assert persisted["exit_reason"] == "connection_cap_reached"
    assert persisted["observation_count"] == 1
    # The run ended well before its deadline, which is exactly why the reason
    # has to be recorded rather than inferred from elapsed time.
    assert persisted["elapsed_seconds"] < 10


def test_observer_cli_defaults_match_the_live_recommendation() -> None:
    source = (TOOLS / "tls_observer.py").read_text(encoding="utf-8")
    assert "default=RECOMMENDED_LIVE_SECONDS" in source
    assert "default=RECOMMENDED_LIVE_MAX_CONNECTIONS" in source
    # No superseded synthetic default survives on the production CLI path.
    assert "default=30.0" not in source


def test_observer_run_summary_carries_no_payload_or_peer_address(tmp_path: Path) -> None:
    cert_dir = tmp_path / "certs"
    local_ca.generate(cert_dir, hostname="p0c2a.test", days=1)
    port, ready = _free_port(), threading.Event()
    log = tmp_path / "privacy.json"

    def server() -> None:
        tls_observer.run_observer(
            cert_dir / "server.crt", cert_dir / "server.key", port, "127.0.0.1",
            max_connections=1, total_timeout=10, ready_event=ready, log_path=log,
            required_sni="p0c2a.test",
        )

    thread = threading.Thread(target=server)
    thread.start()
    assert ready.wait(2)
    context = ssl.create_default_context(cafile=str(cert_dir / "ca.crt"))
    with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
        with context.wrap_socket(raw, server_hostname="p0c2a.test") as client:
            client.sendall(
                b"GET /objects/42?token=TOPSECRET HTTP/1.1\r\n"
                b"Host: p0c2a.test\r\nAuthorization: SECRET-VALUE\r\n\r\n"
            )
    thread.join(5)
    assert not thread.is_alive()
    text = log.read_text(encoding="utf-8")
    assert "TOPSECRET" not in text and "SECRET-VALUE" not in text
    assert "127.0.0.1" not in text
