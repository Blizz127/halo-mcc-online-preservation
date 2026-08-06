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
        "remote_tip": "b" * 40, "status": "", "ahead_behind": "0\t1",
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
        "20.184.144.194", cert_dir / "server.crt", cert_dir / "server.key",
        tmp_path / "run.pid", tmp_path / "run.ready", tmp_path / "run.json",
        "main", "a" * 40, "b" * 40, "b" * 40, tmp_path,
        prefix, wine, thumbprint, dependencies=dependencies,
    )
    after = sorted(str(path) for path in tmp_path.rglob("*"))
    assert result["pass"] is True
    assert before == after
    failed = p0c2d_preflight.run_preflight(
        "127.0.0.1", cert_dir / "server.crt", cert_dir / "server.key",
        tmp_path / "run.pid", tmp_path / "run.ready", tmp_path / "run.json",
        "main", "a" * 40, "b" * 40, "b" * 40, tmp_path,
        prefix, wine, thumbprint, dependencies=dependencies,
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
        "remote": "b" * 40, "status": "", "ahead": "0\t1",
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
            "20.184.144.194", cert_dir / "server.crt", cert_dir / "server.key",
            tmp_path / "out.pid", tmp_path / "out.ready", tmp_path / "out.json",
            "main", "a" * 40, "b" * 40, "b" * 40, tmp_path,
            prefix, wine, thumbprint, dependencies=deps,
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
        "20.184.144.194", cert_dir / "server.crt", cert_dir / "server.key",
        Path(__file__).resolve().parents[1] / "must-not-create.pid",
        tmp_path / "out.ready", tmp_path / "out.json",
        "main", "a" * 40, "b" * 40, "b" * 40,
        Path(__file__).resolve().parents[1], prefix, wine, thumbprint,
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
