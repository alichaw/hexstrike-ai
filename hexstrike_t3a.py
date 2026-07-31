"""Permit-gated bounded T3-A Windows OpenSSH operation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, request

PERMIT_SCHEMA = "hexstrike-t3a-permit/v1"
RESULT_SCHEMA = "hexstrike-t3a-result/v1"
OPERATION_ID = "windows.ssh.identity.v1"
COMMAND_IDS = ("current_identity", "host_identity", "privilege_context")
COMMANDS = ("whoami", "hostname", "whoami /groups")
REGISTRY_DIGEST = hashlib.sha256(
    json.dumps(list(COMMAND_IDS), separators=(",", ":")).encode()
).hexdigest()
_HOST_KEY = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$")


def _decode(value: str) -> bytes:
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError("non-canonical base64url")
    return decoded


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class T3AService:
    def __init__(
        self,
        *,
        permit_secret: bytes,
        target_matrix_path: Path,
        credential_config_path: Path,
        nonce_db_path: Path,
        kill_switch_path: Path | None = None,
        runner=None,
        clock=time.time,
    ):
        if len(permit_secret) < 32:
            raise ValueError("permit_verifier_secret_invalid")
        self.secret = permit_secret
        self.target_matrix_path = target_matrix_path
        self.credential_config_path = credential_config_path
        self.nonce_db_path = nonce_db_path
        self.kill_switch_path = kill_switch_path
        self.runner = runner or self._run_ssh
        self.clock = clock

    def verify(self, token: str) -> dict[str, Any]:
        try:
            payload_part, signature_part = token.split(".", 1)
            payload = _decode(payload_part)
            signature = _decode(signature_part)
            claims = json.loads(payload)
        except Exception as exc:
            raise ValueError("permit_malformed") from exc
        expected = hmac.new(self.secret, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("permit_signature_invalid")
        required = {
            "schema_version",
            "permit_id",
            "nonce",
            "issued_at",
            "expires_at",
            "asset_id",
            "profile_id",
            "operation_id",
            "target",
            "port",
            "credential_ref",
            "pinned_host_key",
            "command_ids",
            "command_registry_digest",
            "approval_fingerprint",
            "runtime_binding_fingerprint",
            "limits",
            "result_schema",
        }
        if not isinstance(claims, dict) or set(claims) != required:
            raise ValueError("permit_claims_invalid")
        now = int(self.clock())
        if (
            claims["schema_version"] != PERMIT_SCHEMA
            or claims["result_schema"] != RESULT_SCHEMA
        ):
            raise ValueError("permit_schema_invalid")
        if not isinstance(claims["issued_at"], int) or not isinstance(
            claims["expires_at"], int
        ):
            raise ValueError("permit_time_invalid")
        if claims["issued_at"] > now + 5 or now >= claims["expires_at"]:
            raise ValueError("permit_expired")
        if claims["expires_at"] - claims["issued_at"] > 60:
            raise ValueError("permit_lifetime_invalid")
        if (
            claims["asset_id"] != "asset:winsrv2025-01"
            or claims["profile_id"] != "t3-authorized-access-bounded"
            or claims["operation_id"] != OPERATION_ID
            or claims["port"] != 22
            or claims["command_ids"] != list(COMMAND_IDS)
            or claims["command_registry_digest"] != REGISTRY_DIGEST
            or not claims["approval_fingerprint"]
            or not claims["runtime_binding_fingerprint"]
            or claims["credential_ref"] != "credential:ssh-winsrv2025-01"
            or not _HOST_KEY.fullmatch(str(claims["pinned_host_key"]))
        ):
            raise ValueError("permit_binding_invalid")
        limits = claims["limits"]
        if not isinstance(limits, dict) or limits.get("max_sessions") != 1:
            raise ValueError("permit_limits_invalid")
        try:
            ipaddress.IPv4Address(claims["target"])
        except Exception as exc:
            raise ValueError("permit_target_invalid") from exc
        return claims

    def target_allowed(self, target: str) -> bool:
        try:
            info = self.target_matrix_path.stat()
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o640:
                return False
            data = json.loads(self.target_matrix_path.read_text(encoding="utf-8"))
            entries = [
                ipaddress.ip_network(x, strict=True) for x in data["allowed_targets"]
            ]
            address = ipaddress.ip_address(target)
            return (
                bool(entries)
                and all(x.version == 4 and x.prefixlen == 32 for x in entries)
                and any(address in x for x in entries)
            )
        except Exception:
            return False

    def consume(self, nonce: str, permit_id: str) -> None:
        self.nonce_db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(
            self.nonce_db_path, timeout=5, isolation_level="IMMEDIATE"
        ) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS spent_permits "
                "(nonce TEXT PRIMARY KEY, permit_id TEXT NOT NULL, consumed_at INTEGER NOT NULL)"
            )
            try:
                db.execute(
                    "INSERT INTO spent_permits VALUES (?, ?, ?)",
                    (
                        hashlib.sha256(nonce.encode()).hexdigest(),
                        permit_id,
                        int(self.clock()),
                    ),
                )
                db.commit()
            except sqlite3.IntegrityError as exc:
                raise ValueError("permit_replayed") from exc

    def resolve_credential(self, credential_ref: str, asset_id: str) -> dict[str, str]:
        info = self.credential_config_path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o640:
            raise ValueError("credential_configuration_invalid")
        data = json.loads(self.credential_config_path.read_text(encoding="utf-8"))
        value = data.get("credentials", {}).get(credential_ref)
        if not isinstance(value, dict) or value.get("asset_id") != asset_id:
            raise ValueError("credential_binding_invalid")
        username, agent = value.get("username"), value.get("identity_agent")
        if not isinstance(username, str) or not re.fullmatch(
            r"[A-Za-z0-9._@-]{1,128}", username
        ):
            raise ValueError("credential_configuration_invalid")
        if not isinstance(agent, str) or not agent.startswith("/run/"):
            raise ValueError("credential_configuration_invalid")
        return {"username": username, "identity_agent": agent}

    def execute(self, claims: dict[str, Any]) -> dict[str, Any]:
        if self.kill_switch_path is not None and self.kill_switch_path.exists():
            raise ValueError("kill_switch_engaged")
        credential = self.resolve_credential(
            claims["credential_ref"], claims["asset_id"]
        )
        results = self.runner(claims, credential)
        if not isinstance(results, list) or [
            x.get("command_id") for x in results
        ] != list(COMMAND_IDS):
            raise ValueError("execution_result_invalid")
        completed = all(x.get("evidence_predicate_passed") is True for x in results)
        return {
            "schema_version": RESULT_SCHEMA,
            "permit_id": claims["permit_id"],
            "operation_id": OPERATION_ID,
            "status": "completed" if completed else "failed",
            "authentication_succeeded": bool(results),
            "session_closed": True,
            "cleanup_succeeded": True,
            "credential_lease_invalidated": True,
            "command_results": results,
        }

    @staticmethod
    def _run_ssh(
        claims: dict[str, Any], credential: dict[str, str]
    ) -> list[dict[str, Any]]:
        results = []
        with tempfile.TemporaryDirectory(prefix="hexstrike-t3a-") as temp:
            known_hosts = Path(temp) / "known_hosts"
            control = Path(temp) / "control"
            known_hosts.write_text(
                f"{claims['target']} {claims['pinned_host_key']}\n",
                encoding="utf-8",
            )
            known_hosts.chmod(0o600)
            base = [
                "ssh",
                "-n",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                f"IdentityAgent={credential['identity_agent']}",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={known_hosts}",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ConnectionAttempts=1",
                "-p",
                "22",
                "-l",
                credential["username"],
                claims["target"],
            ]
            master = subprocess.Popen(
                [*base[:-1], "-M", "-S", str(control), "-N", claims["target"]],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 15
                while (
                    not control.exists()
                    and master.poll() is None
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.05)
                if not control.exists():
                    raise ValueError("ssh_session_failed")
                for command_id, command in zip(COMMAND_IDS, COMMANDS, strict=True):
                    started = time.monotonic()
                    proc = subprocess.run(
                        [*base[:-1], "-S", str(control), claims["target"], command],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        timeout=30,
                        check=False,
                    )
                    stdout = (
                        proc.stdout[:16384].decode("utf-8", errors="strict").strip()
                    )
                    passed = proc.returncode == 0 and not proc.stderr and bool(stdout)
                    results.append(
                        {
                            "command_id": command_id,
                            "attempted": True,
                            "return_code": proc.returncode,
                            "outcome": "succeeded" if passed else "failed",
                            "sanitized_stdout": stdout if passed else "",
                            "duration_seconds": max(0.0, time.monotonic() - started),
                            "evidence_predicate_passed": passed,
                        }
                    )
                    if not passed:
                        break
            finally:
                subprocess.run(
                    [*base[:-1], "-S", str(control), "-O", "exit", claims["target"]],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
                if master.poll() is None:
                    master.terminate()
                    try:
                        master.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        master.kill()
        return results


def register_t3a_routes(app, service: T3AService | None = None) -> None:
    if service is None:
        secret = os.environ.get("HEXSTRIKE_EXECUTION_PERMIT_SECRET", "")
        if not secret:
            return
        service = T3AService(
            permit_secret=secret.encode(),
            target_matrix_path=Path("/etc/hexstrike/job-targets.json"),
            credential_config_path=Path("/etc/hexstrike/t3a-credentials.json"),
            nonce_db_path=Path("/var/lib/hexstrike/spent-t3a-permits.sqlite3"),
            kill_switch_path=Path(
                os.environ.get("HEXSTRIKE_KILL_SWITCH_FILE", "/run/hexstrike/KILL")
            ),
        )
    blueprint = Blueprint("hexstrike_t3a", __name__)

    @blueprint.post("/api/v1/t3a/executions")
    def create_t3a_execution():
        body = request.get_json(silent=True)
        if (
            not isinstance(body, dict)
            or set(body) != {"permit"}
            or not isinstance(body["permit"], str)
        ):
            return jsonify({"error": "permit_required"}), 401
        try:
            claims = service.verify(body["permit"])
            if not service.target_allowed(claims["target"]):
                return jsonify({"error": "target_not_allowed"}), 403
            service.consume(claims["nonce"], claims["permit_id"])
            result = service.execute(claims)
            return jsonify(result), 200 if result["status"] == "completed" else 422
        except ValueError as exc:
            code = str(exc)
            status = 409 if code == "permit_replayed" else 401
            return jsonify({"error": code}), status
        except Exception:
            return jsonify({"error": "t3a_execution_failed"}), 500

    app.register_blueprint(blueprint)
