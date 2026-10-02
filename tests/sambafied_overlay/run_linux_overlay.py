#!/usr/bin/env python3
"""Run the public two-user shadow-SMB contract against a local rustsmb binary.

The temporary fixture, including the server's account JSON, is never copied to
the artifact directory.  The retained reports deliberately contain neither
passwords nor file payloads.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parents[1]
DEFAULT_BINARY = Path("target/debug/rustsmb")
READY_TIMEOUT_SECONDS = 30
SHUTDOWN_TIMEOUT_SECONDS = 10
MAX_POLICY_DOCUMENT_BYTES = 16 * 1024 * 1024


def policy_document_digest(root: Path) -> tuple[str, bytes]:
    """Compare server-created authority without retaining its contents or path."""
    documents = list(root.glob("*.policy.json"))
    if len(documents) != 1:
        raise RuntimeError("the fixture did not create exactly one shared policy document")
    document = documents[0]
    if document.is_symlink() or not document.is_file():
        raise RuntimeError("the policy document is not an owned regular file")
    with document.open("rb") as source:
        content = source.read(MAX_POLICY_DOCUMENT_BYTES + 1)
    if len(content) > MAX_POLICY_DOCUMENT_BYTES:
        raise RuntimeError("the policy document exceeded the bounded read limit")
    parsed = json.loads(content)
    if not isinstance(parsed, dict) or not all(key in parsed for key in ("revision", "policy", "changes")):
        raise RuntimeError("the policy document omitted its revision, policy or audit")
    return document.name, hashlib.sha256(content).digest()


def choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_listener(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("rustsmb exited before its listener became ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("rustsmb did not become ready before the bounded deadline")


def shadow_config(base: Path, private: Path) -> dict[str, Any]:
    policy = {
        "active_bytes": 10_485_760,
        "active_files": 1_000,
        "retained_bytes": 10_485_760,
        "temporary_bytes": 10_485_760,
        "max_file_bytes": 1_048_576,
        "snapshot_limit": 20,
        "history_limit": 20,
        "snapshot_ttl_seconds": 86_400,
        "recovery_protection_seconds": 3_600,
        "trash_ttl_seconds": 86_400,
    }

    def principal(name: str) -> dict[str, Any]:
        return {
            "root": str(private),
            "base": str(base),
            "identity": {
                "organization": "public-ci",
                "share": "games-fixture",
                "principal": f"{name}-stable-id",
                "base_version": "v1",
            },
            "policy": policy,
        }

    return {"games": {"alice": principal("alice"), "bob": principal("bob")}}


def runner_metadata(binary: Path) -> dict[str, Any]:
    source: dict[str, Any] = {
        "githubSha": os.environ.get("GITHUB_SHA"),
        "gitHead": None,
        "workingTree": "unavailable",
    }
    try:
        status = subprocess.run(
            ["git", "-C", str(REPOSITORY_ROOT), "status", "--porcelain"],
            capture_output=True,
            check=True,
            text=True,
        )
        if status.stdout:
            source["workingTree"] = "dirty"
        else:
            head = subprocess.run(
                ["git", "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"],
                capture_output=True,
                check=True,
                text=True,
            ).stdout.strip()
            if head:
                source["gitHead"] = head
                source["workingTree"] = "clean"
    except (OSError, subprocess.CalledProcessError):
        pass

    return {
        "binary": {"sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
        "source": source,
    }


def write_report(
    path: Path,
    outcome: str,
    port: int | None,
    failure: str | None,
    metadata: dict[str, Any],
) -> None:
    report = {
        "schemaVersion": 1,
        "kind": "sambafied-linux-overlay-runner",
        "finishedAt": datetime.now(UTC).isoformat(),
        "outcome": outcome,
        "server": {"host": "127.0.0.1", "port": port, "share": "games"},
        "failure": failure,
        "metadata": metadata,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def terminate_owned_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=SHUTDOWN_TIMEOUT_SECONDS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-bin", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--artifacts-dir", type=Path, required=True)
    args = parser.parse_args()

    if os.name != "posix":
        raise SystemExit("This native io_uring contract runner requires Linux.")
    binary = args.server_bin.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise SystemExit("The requested rustsmb binary is missing or not executable.")

    artifacts = args.artifacts_dir.resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    report_path, actuator_report = artifacts / "runner-report.json", artifacts / "actuator-report.json"
    log_path = artifacts / "rustsmb.log"
    port: int | None = None
    process: subprocess.Popen[bytes] | None = None
    outcome, failure = "FAIL", None
    metadata = runner_metadata(binary)

    try:
        with tempfile.TemporaryDirectory(prefix="sambafied-overlay-") as temporary:
            try:
                fixture = Path(temporary).resolve()
                base, private, policies = fixture / "base", fixture / "private", fixture / "policies"
                base.mkdir()
                private.mkdir()
                policies.mkdir(mode=0o700)
                fixture_file = ROOT / "BASE.TXT"
                base_file = base / "BASE.TXT"
                base_file.write_bytes(fixture_file.read_bytes())
                config_path = fixture / "shadows.json"
                config_path.write_text(json.dumps(shadow_config(base, private)), encoding="utf-8")
                port = choose_port()
                accounts = {"alice": secrets.token_urlsafe(32), "bob": secrets.token_urlsafe(32)}
                command = [
                    str(binary), "--users-stdin", "--bind", f"127.0.0.1:{port}",
                    "--share", f"games={base}", "--shadow-config", str(config_path), "--require-signing",
                    "--shadow-policy-root", str(policies),
                ]
                with log_path.open("wb") as log_file:
                    process = subprocess.Popen(
                        command, stdin=subprocess.PIPE, stdout=log_file, stderr=subprocess.STDOUT,
                        cwd=binary.parent.parent.parent,
                        env={**os.environ, "RUST_LOG": "info"},
                    )
                    assert process.stdin is not None
                    process.stdin.write(json.dumps(accounts).encode("utf-8"))
                    process.stdin.close()
                    wait_for_listener(process, port)
                    actuator_config = {
                        "server": {"host": "127.0.0.1", "port": port}, "share": "games",
                        "baseFile": "BASE.TXT", "baseFixture": str(fixture_file), "hostBaseFile": str(base_file),
                        "operationTimeoutSeconds": 15,
                        "alice": {"username": "alice", "passwordEnv": "SAMBAFIED_OVERLAY_ALICE_PASSWORD", "saveFile": "alice-save.sav"},
                        "bob": {"username": "bob", "passwordEnv": "SAMBAFIED_OVERLAY_BOB_PASSWORD", "saveFile": "alice-save.sav"},
                        "modernListener": {"smb1NegativeTest": True},
                    }
                    actuator_config_path = fixture / "actuator-config.json"
                    actuator_config_path.write_text(json.dumps(actuator_config), encoding="utf-8")
                    actuator_env = {**os.environ, "SAMBAFIED_OVERLAY_ALICE_PASSWORD": accounts["alice"], "SAMBAFIED_OVERLAY_BOB_PASSWORD": accounts["bob"]}
                    result = subprocess.run(
                        [sys.executable, str(ROOT / "overlay_smb_two_user.py"), "--config", str(actuator_config_path), "--report", str(actuator_report)],
                        cwd=ROOT, env=actuator_env, timeout=120, check=False,
                    )
                    if result.returncode != 0:
                        raise RuntimeError("the two-user overlay actuator returned a non-zero status")
                    terminate_owned_process(process)
                    before_restart = policy_document_digest(policies)
                    process = subprocess.Popen(
                        command, stdin=subprocess.PIPE, stdout=log_file, stderr=subprocess.STDOUT,
                        cwd=binary.parent.parent.parent,
                        env={**os.environ, "RUST_LOG": "info"},
                    )
                    assert process.stdin is not None
                    process.stdin.write(json.dumps(accounts).encode("utf-8"))
                    process.stdin.close()
                    wait_for_listener(process, port)
                    if policy_document_digest(policies) != before_restart:
                        raise RuntimeError("the shared policy document changed across server restart")
                    terminate_owned_process(process)
                    if policy_document_digest(policies) != before_restart:
                        raise RuntimeError("the shared policy document changed on restarted server shutdown")
                    metadata["policyCatalog"] = {"sharedDocumentCount": 1, "restartUnchanged": True}
                if hashlib.sha256(base_file.read_bytes()).digest() != hashlib.sha256(fixture_file.read_bytes()).digest():
                    raise RuntimeError("the base fixture changed during the SMB contract")
            finally:
                terminate_owned_process(process)
        outcome = "PASS"
    except Exception as error:
        failure = f"{type(error).__name__}"
        print(f"FAIL: {failure}", file=sys.stderr)
    finally:
        terminate_owned_process(process)
        write_report(report_path, outcome, port, failure, metadata)
    return 0 if outcome == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
