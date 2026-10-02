#!/usr/bin/env python3
"""Bounded two-user SMB overlay contract actuator.

Passwords come only from an environment variable or protected local JSON file.
The report deliberately contains no passwords, credential paths, or payloads.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, TypeVar

OUTCOMES = {"PASS", "FAIL", "NOT_RUN"}
MAX_NBSS_FRAME = 1024 * 1024
T = TypeVar("T")


class NotRun(Exception):
    pass


class TimedOut(Exception):
    pass


class Actuator:
    def __init__(self, config: dict[str, Any], report_path: Path) -> None:
        self.config, self.report_path = config, report_path
        self.run_id = str(uuid.uuid4())
        self.started_at = datetime.now(UTC).isoformat()
        self.steps: list[dict[str, str]] = []

    def step(self, name: str, outcome: str, detail: str) -> None:
        if outcome not in OUTCOMES:
            raise ValueError(f"invalid outcome {outcome}")
        self.steps.append({"name": name, "outcome": outcome, "detail": detail})

    def write_report(self, outcome: str) -> None:
        server = self.config.get("server", {})
        report = {
            "schemaVersion": 1,
            "kind": "two-user-overlay-smb-actuator",
            "runId": self.run_id,
            "startedAt": self.started_at,
            "finishedAt": datetime.now(UTC).isoformat(),
            "outcome": outcome,
            "client": {"python": sys.version.split()[0], "platform": platform.platform()},
            "target": {
                "host": server.get("host"),
                "port": server.get("port"),
                "share": self.config.get("share"),
                "accounts": [self.config.get("alice", {}).get("username"), self.config.get("bob", {}).get("username")],
            },
            "steps": self.steps,
        }
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise NotRun(f"configuration file is missing: {path}") from error
    except json.JSONDecodeError as error:
        raise NotRun(f"configuration file is invalid JSON: {error.msg}") from error
    if not isinstance(config, dict):
        raise NotRun("configuration root must be a JSON object")
    return config


def required(config: dict[str, Any], key: str, expected: type) -> Any:
    value = config.get(key)
    if not isinstance(value, expected) or (expected is str and not value):
        raise NotRun(f"{key} is required")
    return value


def assert_restricted_acl(path: Path) -> None:
    if os.name == "nt":
        try:
            acl = subprocess.run(["icacls", str(path)], capture_output=True, text=True, check=True, timeout=10).stdout.lower()
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            raise NotRun("could not inspect credential-file ACL") from error
        if any(principal in acl for principal in ("everyone:", "builtin\\users:", "authenticated users:")):
            raise NotRun("credential file ACL grants a broad principal; restrict it to the test operator")
    elif path.stat().st_mode & 0o077:
        raise NotRun("credential file must not be group/world accessible (expected mode 0600)")


def password(account: dict[str, Any]) -> str:
    env_name, credential_file = account.get("passwordEnv"), account.get("credentialsFile")
    if bool(env_name) == bool(credential_file):
        raise NotRun("each account must configure exactly one of passwordEnv or credentialsFile")
    if env_name:
        if not isinstance(env_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_name):
            raise NotRun("passwordEnv is not a valid environment-variable name")
        value = os.environ.get(env_name)
        if not value:
            raise NotRun(f"required credential environment variable is unset: {env_name}")
        return value
    path = Path(str(credential_file)).expanduser()
    if not path.is_file():
        raise NotRun("credential file is missing")
    assert_restricted_acl(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))["password"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise NotRun("credential file must contain a JSON password field") from error
    if not isinstance(value, str) or not value:
        raise NotRun("credential file password must be a non-empty string")
    return value


def bounded(timeout: int, operation: Callable[[], T]) -> T:
    result: list[T] = []
    errors: list[BaseException] = []

    def invoke() -> None:
        try:
            result.append(operation())
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=invoke, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise TimedOut(f"operation exceeded configured {timeout}-second timeout")
    if errors:
        raise errors[0]
    return result[0]


def runtime_inputs(config: dict[str, Any]) -> tuple[str, int, str, str, Path, Path, int, dict[str, Any], dict[str, Any]]:
    server = required(config, "server", dict)
    host, port = server.get("host"), server.get("port")
    if not isinstance(host, str) or not host or not isinstance(port, int) or not 1 <= port <= 65535:
        raise NotRun("server.host and server.port are required")
    share, base_file = required(config, "share", str), required(config, "baseFile", str)
    fixture, host_base = Path(required(config, "baseFixture", str)), Path(required(config, "hostBaseFile", str))
    timeout = config.get("operationTimeoutSeconds", 15)
    if not isinstance(timeout, int) or not 1 <= timeout <= 60:
        raise NotRun("operationTimeoutSeconds must be an integer from 1 to 60")
    alice, bob = required(config, "alice", dict), required(config, "bob", dict)
    for label, account in (("alice", alice), ("bob", bob)):
        if not isinstance(account.get("username"), str) or not account["username"]:
            raise NotRun(f"{label}.username is required")
        if not isinstance(account.get("saveFile"), str) or not account["saveFile"]:
            raise NotRun(f"{label}.saveFile is required")
    if alice["saveFile"] != bob["saveFile"]:
        raise NotRun("alice.saveFile and bob.saveFile must name the same path")
    if not fixture.is_file() or not host_base.is_file():
        raise NotRun("baseFixture and hostBaseFile must both be regular files")
    return host, port, share, base_file, fixture, host_base, timeout, alice, bob


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    """Read one bounded NBSS field, distinguishing closure from a complete reply."""
    received = bytearray()
    while len(received) < size:
        chunk = connection.recv(size - len(received))
        if not chunk:
            if not received:
                return b""
            raise RuntimeError("listener closed a truncated SMB1 response")
        received.extend(chunk)
    return bytes(received)


def _smb1_negotiate_request() -> bytes:
    # SMB1 header: command NEGOTIATE, normal client flags, followed by WordCount
    # zero and a two-byte ByteCount containing one dialect string.
    dialects = b"\x02NT LM 0.12\x00"
    header = (
        b"\xffSMB\x72"  # protocol and SMB_COM_NEGOTIATE
        + b"\x00" * 4  # NT status
        + b"\x18"  # flags: case-insensitive paths and canonicalized paths
        + b"\x53\xc8"  # flags2: long names, NT status, Unicode capability
        + b"\x00" * 12  # PID high, signature, reserved
        + b"\x00" * 8  # TID, PID low, UID, MID
    )
    assert len(header) == 32
    smb1 = header + b"\x00" + len(dialects).to_bytes(2, "little") + dialects
    return b"\x00" + len(smb1).to_bytes(3, "big") + smb1


def smb1_negative(host: str, port: int, timeout: int) -> None:
    """Require a closed/reset connection or an explicit SMB1 error response."""
    packet = _smb1_negotiate_request()
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(packet)
        try:
            nbss = _recv_exact(connection, 4)
        except (ConnectionResetError, BrokenPipeError):
            return
        if not nbss:
            return
        if nbss[0] != 0:
            raise RuntimeError("listener returned a non-session SMB1 response")
        frame_size = int.from_bytes(nbss[1:], "big")
        if not 32 <= frame_size <= MAX_NBSS_FRAME:
            raise RuntimeError("listener returned an invalid SMB1 response size")
        response = _recv_exact(connection, frame_size)
    if response[:4] != b"\xffSMB":
        raise RuntimeError("listener did not explicitly reject the SMB1 negotiate request")
    status = int.from_bytes(response[5:9], "little")
    if status == 0:
        raise RuntimeError("listener accepted the SMB1 negotiate request")


def exception_summary(error: BaseException) -> str:
    """Keep reports useful without exposing library exception text or credentials."""
    if isinstance(error, NotRun):
        return str(error)
    if isinstance(error, TimedOut):
        return str(error)
    return f"operation failed ({type(error).__name__})"


def two_user_overlay(actuator: Actuator) -> None:
    try:
        import smbclient  # type: ignore[import-not-found]
    except ImportError as error:
        raise NotRun("smbprotocol/smbclient is not installed in the selected Python environment") from error
    host, port, share, base_file, fixture, host_base, timeout, alice, bob = runtime_inputs(actuator.config)
    expected_base = fixture.read_bytes()
    if not expected_base:
        raise NotRun("baseFixture must not be empty")
    if host_base.read_bytes() != expected_base:
        raise RuntimeError("host base differs from the immutable fixture before SMB operations")
    actuator.step("host_base_before", "PASS", f"sha256={hashlib.sha256(expected_base).hexdigest()}")
    modern = actuator.config.get("modernListener", {})
    if modern.get("smb1NegativeTest", False):
        bounded(timeout, lambda: smb1_negative(host, port, timeout))
        actuator.step("smb1_negotiate_rejected", "PASS", f"modern listener did not accept SMB1 on {host}:{port}")
    else:
        actuator.step("smb1_negotiate_rejected", "NOT_RUN", "modernListener.smb1NegativeTest is not enabled")

    root = "\\\\" + host + "\\" + share
    base_path, save_path = root + "\\" + base_file, root + "\\" + alice["saveFile"]
    alice_base = f"alice overlay base run={actuator.run_id}\n".encode("ascii")
    alice_save = f"alice overlay save run={actuator.run_id}\n".encode("ascii") + bytes(range(256))

    def connect(account: dict[str, Any]) -> dict[str, Any]:
        cache: dict[str, Any] = {}
        bounded(timeout, lambda: smbclient.register_session(host, username=account["username"], password=password(account), port=port, connection_timeout=timeout, connection_cache=cache))
        expected_key = f"{host.lower()}:{port}"
        if set(cache) != {expected_key}:
            raise RuntimeError("SMB client opened an unexpected connection target")
        return cache

    def read_file(cache: dict[str, Any], path: str) -> bytes:
        def operation() -> bytes:
            with smbclient.open_file(path, mode="rb", port=port, connection_cache=cache) as source:
                return source.read()
        return bounded(timeout, operation)

    def write_file(cache: dict[str, Any], path: str, payload: bytes) -> None:
        def operation() -> None:
            with smbclient.open_file(path, mode="wb", port=port, connection_cache=cache) as target:
                target.write(payload)
                target.flush()
        bounded(timeout, operation)

    alice_cache: dict[str, Any] | None = None
    alice_reconnect_cache: dict[str, Any] | None = None
    bob_cache: dict[str, Any] | None = None
    try:
        alice_cache = connect(alice)
        if read_file(alice_cache, base_path) != expected_base:
            raise RuntimeError("Alice did not start with the immutable base bytes")
        actuator.step("alice_reads_base", "PASS", "Alice observed immutable base before writes")
        write_file(alice_cache, base_path, alice_base)
        write_file(alice_cache, save_path, alice_save)
        actuator.step("alice_writes_overlay", "PASS", "Alice wrote base replacement and new save through explicit port")
        smbclient.reset_connection_cache(connection_cache=alice_cache)
        alice_cache = None

        alice_reconnect_cache = connect(alice)
        if read_file(alice_reconnect_cache, base_path) != alice_base or read_file(alice_reconnect_cache, save_path) != alice_save:
            raise RuntimeError("Alice did not observe her own content after reconnect")
        actuator.step("alice_reconnects_own_overlay", "PASS", "Alice observed her base replacement and save after reconnect")

        bob_cache = connect(bob)
        if read_file(bob_cache, base_path) != expected_base:
            raise RuntimeError("Bob observed Alice's base replacement")
        actuator.step("bob_reads_original_base", "PASS", "Bob observed the immutable base bytes")
        try:
            read_file(bob_cache, save_path)
        except FileNotFoundError:
            actuator.step("bob_cannot_see_alice_save", "PASS", "Alice save was absent from Bob's overlay")
        except OSError as error:
            if error.errno != errno.ENOENT:
                raise
            actuator.step("bob_cannot_see_alice_save", "PASS", "Alice save was absent from Bob's overlay")
        else:
            raise RuntimeError("Bob could read Alice's save")
    finally:
        for cache in (alice_cache, alice_reconnect_cache, bob_cache):
            if cache is not None:
                try:
                    smbclient.reset_connection_cache(connection_cache=cache)
                except Exception:
                    pass

    if host_base.read_bytes() != expected_base:
        raise RuntimeError("host base changed after overlay operations")
    actuator.step("host_base_after", "PASS", "host immutable base bytes remained unchanged")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the two-user SMB overlay actuator")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    actuator = Actuator({}, args.report)
    try:
        actuator.config = load_config(args.config)
        two_user_overlay(actuator)
    except NotRun as error:
        detail = exception_summary(error)
        actuator.step("prerequisite", "NOT_RUN", detail)
        actuator.write_report("NOT_RUN")
        print(f"NOT RUN: {detail}")
        return 2
    except Exception as error:
        detail = exception_summary(error)
        actuator.step("failure", "FAIL", detail)
        actuator.write_report("FAIL")
        print(f"FAIL: {detail}")
        return 1
    actuator.write_report("PASS")
    print("PASS: two-user overlay contract completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
