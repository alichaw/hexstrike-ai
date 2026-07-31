"""Permit-gated fixed T3-B Windows OpenSSH enumeration."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, request
from hexstrike_t3a import T3AService, _decode

PERMIT_SCHEMA = "hexstrike-t3b-permit/v1"
RESULT_SCHEMA = "hexstrike-t3b-result/v1"
OPERATION_ID = "windows.host.enumeration.readonly.v1"
PROFILE_ID = "windows-host-enumeration-readonly"
STAGE = "T3-B"
_HOST_KEY = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$")

SCRIPTS = {
    "windows_os_version": (
        "Get-CimInstance Win32_OperatingSystem | "
        "Select-Object Caption,Version,BuildNumber | ConvertTo-Json -Compress"
    ),
    "windows_network_configuration": (
        "Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv6Address | "
        "ConvertTo-Json -Depth 4 -Compress"
    ),
    "windows_listening_ports": (
        "Get-NetTCPConnection -State Listen | Select-Object "
        "LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress"
    ),
    "windows_running_services": (
        "Get-Service | Where-Object Status -eq Running | "
        "Select-Object Name,DisplayName,Status | ConvertTo-Json -Compress"
    ),
    "windows_installed_hotfixes": (
        "Get-HotFix | Select-Object HotFixID,InstalledOn,Description | "
        "ConvertTo-Json -Compress"
    ),
}
VERIFIERS = {
    "windows_os_version": "windows_os_identity",
    "windows_network_configuration": "windows_interfaces",
    "windows_listening_ports": "windows_listeners",
    "windows_running_services": "windows_services",
    "windows_installed_hotfixes": "windows_hotfixes",
}


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


DEFINITIONS = {
    action_id: {
        "action_id": action_id,
        "program": "powershell.exe",
        "argv": ("-NoProfile", "-NonInteractive", "-Command", script),
        "verifier": VERIFIERS[action_id],
        "platform": "windows_openssh",
        "enabled": True,
        "read_only": True,
    }
    for action_id, script in SCRIPTS.items()
}
DEFINITION_DIGESTS = {key: _digest(value) for key, value in DEFINITIONS.items()}
REGISTRY_DIGEST = _digest(dict(sorted(DEFINITIONS.items())))


class T3BService(T3AService):
    def verify(self, token: str) -> dict[str, Any]:
        try:
            payload_part, signature_part = token.split(".", 1)
            payload = _decode(payload_part)
            signature = _decode(signature_part)
            claims = json.loads(payload)
        except Exception as exc:
            raise ValueError("permit_malformed") from exc
        if not hmac.compare_digest(
            signature, hmac.new(self.secret, payload, hashlib.sha256).digest()
        ):
            raise ValueError("permit_signature_invalid")
        required = {
            "schema_version",
            "permit_id",
            "nonce",
            "issued_at",
            "expires_at",
            "asset_id",
            "profile_id",
            "stage",
            "operation_id",
            "target",
            "port",
            "credential_ref",
            "pinned_host_key",
            "prerequisite_run_id",
            "approval_fingerprint",
            "runtime_binding_fingerprint",
            "command_ids",
            "registry_digest",
            "definition_digests",
            "limits",
            "result_schema",
        }
        if not isinstance(claims, dict) or set(claims) != required:
            raise ValueError("permit_claims_invalid")
        now = int(self.clock())
        if (
            claims["schema_version"] != PERMIT_SCHEMA
            or claims["result_schema"] != RESULT_SCHEMA
            or claims["asset_id"] != "asset:winsrv2025-01"
            or claims["profile_id"] != PROFILE_ID
            or claims["stage"] != STAGE
            or claims["operation_id"] != OPERATION_ID
            or claims["port"] != 22
            or claims["credential_ref"] != "credential:ssh-winsrv2025-01"
            or claims["command_ids"] != list(SCRIPTS)
            or claims["registry_digest"] != REGISTRY_DIGEST
            or claims["definition_digests"]
            != [DEFINITION_DIGESTS[item] for item in SCRIPTS]
            or not claims["prerequisite_run_id"]
            or not claims["approval_fingerprint"]
            or not claims["runtime_binding_fingerprint"]
            or not _HOST_KEY.fullmatch(str(claims["pinned_host_key"]))
        ):
            raise ValueError("permit_binding_invalid")
        if (
            not isinstance(claims["issued_at"], int)
            or not isinstance(claims["expires_at"], int)
            or claims["issued_at"] > now + 5
            or now >= claims["expires_at"]
            or claims["expires_at"] - claims["issued_at"] > 60
        ):
            raise ValueError("permit_expired")
        limits = claims["limits"]
        if (
            not isinstance(limits, dict)
            or set(limits)
            != {
                "max_commands",
                "max_sessions",
                "per_command_timeout_seconds",
                "total_timeout_seconds",
                "stdout_limit",
                "stderr_limit",
                "total_output_limit",
            }
            or limits.get("max_commands") != 5
            or limits.get("max_sessions") != 1
            or limits.get("per_command_timeout_seconds") != 15
            or limits.get("total_timeout_seconds") != 60
            or limits.get("stdout_limit") != 16_384
            or limits.get("stderr_limit") != 4_096
            or limits.get("total_output_limit") != 50_000
        ):
            raise ValueError("permit_limits_invalid")
        try:
            __import__("ipaddress").IPv4Address(claims["target"])
        except Exception as exc:
            raise ValueError("permit_target_invalid") from exc
        return claims

    def execute(self, claims: dict[str, Any]) -> dict[str, Any]:
        if self.kill_switch_path is not None and self.kill_switch_path.exists():
            raise ValueError("kill_switch_engaged")
        credential = self.resolve_credential(
            claims["credential_ref"], claims["asset_id"]
        )
        results = self.runner(claims, credential)
        if not isinstance(results, list) or [
            item.get("action_id") for item in results
        ] != list(SCRIPTS):
            raise ValueError("execution_result_invalid")
        required_result_fields = {
            "action_id",
            "definition_digest",
            "started_at",
            "completed_at",
            "duration_seconds",
            "exit_status",
            "stdout",
            "stderr",
            "stdout_original_bytes",
            "stdout_retained_bytes",
            "stderr_original_bytes",
            "stderr_retained_bytes",
            "stdout_truncated",
            "stderr_truncated",
            "stdout_decoding_errors",
            "stderr_decoding_errors",
        }
        if any(
            set(item) != required_result_fields
            or item["definition_digest"] != DEFINITION_DIGESTS[item["action_id"]]
            or not isinstance(item["stdout"], str)
            or not isinstance(item["stderr"], str)
            or item["stdout_retained_bytes"] > item["stdout_original_bytes"]
            or item["stderr_retained_bytes"] > item["stderr_original_bytes"]
            or item["stdout_truncated"]
            is not (item["stdout_retained_bytes"] < item["stdout_original_bytes"])
            or item["stderr_truncated"]
            is not (item["stderr_retained_bytes"] < item["stderr_original_bytes"])
            for item in results
        ):
            raise ValueError("execution_result_invalid")
        verified = all(
            item.get("exit_status") == 0
            and item.get("stdout_truncated") is False
            and item.get("stderr_truncated") is False
            and item.get("stdout_decoding_errors") is False
            and item.get("stderr_decoding_errors") is False
            for item in results
        )
        return {
            "schema_version": RESULT_SCHEMA,
            "permit_id": claims["permit_id"],
            "operation_id": OPERATION_ID,
            "status": "verified" if verified else "failed",
            "authentication_succeeded": bool(results),
            "session_closed": True,
            "cleanup_succeeded": True,
            "credential_lease_invalidated": True,
            "action_results": results,
        }

    @staticmethod
    def _run_ssh(
        claims: dict[str, Any], credential: dict[str, str]
    ) -> list[dict[str, Any]]:
        results = []
        with tempfile.TemporaryDirectory(prefix="hexstrike-t3b-") as temp:
            known_hosts = Path(temp) / "known_hosts"
            control = Path(temp) / "control"
            known_hosts.write_text(
                f"{claims['target']} {claims['pinned_host_key']}\n", encoding="utf-8"
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
            ]
            master = subprocess.Popen(
                [*base, "-M", "-S", str(control), "-N", claims["target"]],
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
                total_retained = 0
                for action_id, script in SCRIPTS.items():
                    started = time.monotonic()
                    encoded = base64.b64encode(script.encode("utf-16le")).decode()
                    command = (
                        "powershell.exe -NoLogo -NoProfile -NonInteractive "
                        f"-EncodedCommand {encoded}"
                    )
                    proc = subprocess.run(
                        [*base, "-S", str(control), claims["target"], command],
                        stdin=subprocess.DEVNULL,
                        capture_output=True,
                        timeout=15,
                        check=False,
                    )
                    stdout_original, stderr_original = (
                        len(proc.stdout),
                        len(proc.stderr),
                    )
                    remaining = max(0, 50_000 - total_retained)
                    stdout_raw = proc.stdout[: min(16_384, remaining)]
                    remaining -= len(stdout_raw)
                    stderr_raw = proc.stderr[: min(4_096, remaining)]
                    total_retained += len(stdout_raw) + len(stderr_raw)
                    stdout = stdout_raw.decode("utf-8", errors="replace")
                    stderr = stderr_raw.decode("utf-8", errors="replace")
                    finished = time.time()
                    results.append(
                        {
                            "action_id": action_id,
                            "definition_digest": DEFINITION_DIGESTS[action_id],
                            "started_at": __import__("datetime")
                            .datetime.fromtimestamp(
                                finished - (time.monotonic() - started),
                                __import__("datetime").timezone.utc,
                            )
                            .isoformat(),
                            "completed_at": __import__("datetime")
                            .datetime.fromtimestamp(
                                finished, __import__("datetime").timezone.utc
                            )
                            .isoformat(),
                            "duration_seconds": max(0.0, time.monotonic() - started),
                            "exit_status": proc.returncode,
                            "stdout": stdout,
                            "stderr": stderr,
                            "stdout_original_bytes": stdout_original,
                            "stdout_retained_bytes": len(stdout_raw),
                            "stderr_original_bytes": stderr_original,
                            "stderr_retained_bytes": len(stderr_raw),
                            "stdout_truncated": len(stdout_raw) < stdout_original,
                            "stderr_truncated": len(stderr_raw) < stderr_original,
                            "stdout_decoding_errors": "\ufffd" in stdout,
                            "stderr_decoding_errors": "\ufffd" in stderr,
                        }
                    )
                    if proc.returncode != 0:
                        break
            finally:
                subprocess.run(
                    [*base, "-S", str(control), "-O", "exit", claims["target"]],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=False,
                )
                if master.poll() is None:
                    master.terminate()
        return results


def register_t3b_routes(app, service: T3BService | None = None) -> None:
    if service is None:
        secret = os.environ.get("HEXSTRIKE_EXECUTION_PERMIT_SECRET", "")
        if not secret:
            return
        service = T3BService(
            permit_secret=secret.encode(),
            target_matrix_path=Path("/etc/hexstrike/job-targets.json"),
            credential_config_path=Path("/etc/hexstrike/t3a-credentials.json"),
            nonce_db_path=Path("/var/lib/hexstrike/spent-t3b-permits.sqlite3"),
            kill_switch_path=Path(
                os.environ.get("HEXSTRIKE_KILL_SWITCH_FILE", "/run/hexstrike/KILL")
            ),
            runner=T3BService._run_ssh,
        )
    blueprint = Blueprint("hexstrike_t3b", __name__)

    @blueprint.post("/api/v1/t3b/executions")
    def create_t3b_execution():
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
            return jsonify(result), 200 if result["status"] == "verified" else 422
        except ValueError as exc:
            code = str(exc)
            return jsonify({"error": code}), 409 if code == "permit_replayed" else 401
        except Exception:
            return jsonify({"error": "t3b_execution_failed"}), 500

    app.register_blueprint(blueprint)
