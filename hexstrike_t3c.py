"""Loopback-only, fixed single-asset T3-C synthetic-marker endpoint."""

from __future__ import annotations

import grp
import hashlib
import ipaddress
import json
import logging
import os
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Protocol

from flask import Blueprint, jsonify, request

from hexstrike_t3_authorization import (
    consume_authorization_id,
    validate_authorization_id,
)
from hexstrike_t3_identity import IDENTITY_AGENT_PATH
from hexstrike_t3_config import load_protected_json

ACTION_ID = "t3c.controlled_impact_proof.v1"
SCHEMA = "hexstrike-t3c-result/v2"
SCENARIO_ID = "lab.synthetic-marker.v2"
MARKER_PATH = r"C:\ProgramData\HexStrike\t3c-synthetic-marker.txt"
MARKER_CONTENT = "HEXSTRIKE_T3C_SYNTHETIC_MARKER_V2"
MARKER_DIGEST = hashlib.sha256(MARKER_CONTENT.encode()).hexdigest()
_LOGGER = logging.getLogger("hexstrike.t3c")


class MarkerConnector(Protocol):
    def exists(self) -> bool: ...
    def create(self) -> None: ...
    def digest(self) -> str: ...
    def cleanup(self) -> None: ...


class FixedSshMarkerConnector:
    """Execute only registered PowerShell snippets against protected configuration."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.deadline = time.monotonic() + config["maximum_duration_seconds"]

    def _run(self, script: str) -> str:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("fixed_marker_duration_exceeded")
        completed = subprocess.run(
            [
                "ssh",
                "-n",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                f"IdentityAgent={self.config['identity_agent']}",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={self.config['pinned_host_key_file']}",
                "-o",
                "ConnectTimeout=15",
                "-o",
                "ConnectionAttempts=1",
                f"{self.config['username']}@{self.config['target']}",
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            capture_output=True,
            timeout=remaining,
            check=False,
        )
        if (
            completed.returncode != 0
            or completed.stderr
            or len(completed.stdout) > 4096
        ):
            raise RuntimeError("fixed_marker_connector_failed")
        return completed.stdout.decode("utf-8", errors="strict").strip()

    def exists(self) -> bool:
        return (
            self._run(f"[bool](Test-Path -LiteralPath '{MARKER_PATH}' -PathType Leaf)")
            == "True"
        )

    def create(self) -> None:
        self._run(
            f"[IO.File]::WriteAllText('{MARKER_PATH}','{MARKER_CONTENT}',"
            "[Text.UTF8Encoding]::new($false))"
        )

    def digest(self) -> str:
        return self._run(
            f"(Get-FileHash -LiteralPath '{MARKER_PATH}' -Algorithm SHA256).Hash"
        ).lower()

    def cleanup(self) -> None:
        self._run(f"Remove-Item -LiteralPath '{MARKER_PATH}' -Force")


class T3CService:
    """Validate gates before resolving credentials or invoking the fixed connector."""

    def __init__(
        self,
        config_path: str | Path | None = None,
        reachability_path: str | Path | None = None,
        connector_factory=None,
        nonce_db_path: str | Path | None = None,
        clock=time.time,
    ):
        selected_path = config_path or os.environ.get("HEXSTRIKE_T3C_CONFIG", "")
        self.require_protected_config = config_path is None
        self.config_path = Path(selected_path)
        self.reachability_path = Path(
            reachability_path
            or os.environ.get(
                "HEXSTRIKE_T3_REACHABILITY_CONFIG",
                "/etc/hexstrike/t3-reachability.json",
            )
        )
        self.nonce_db_path = Path(
            nonce_db_path
            or (
                "/var/lib/hexstrike/spent-poc-authorizations.sqlite3"
                if config_path is None
                else self.config_path.with_suffix(".sqlite3")
            )
        )
        self.clock = clock
        self.connector_factory = connector_factory or FixedSshMarkerConnector
        self.connector_invoked = False
        self.credential_provider_invoked = False
        self.target_resolved = False

    def _config(self) -> dict[str, Any]:
        if not str(self.config_path) or not self.config_path.is_file():
            raise ValueError("scenario_configuration_missing")
        if self.require_protected_config:
            info = self.config_path.stat()
            if (
                info.st_uid != 0
                or grp.getgrgid(info.st_gid).gr_name != "hexstrike"
                or stat.S_IMODE(info.st_mode) != 0o640
            ):
                raise ValueError("scenario_configuration_not_protected")
        value = json.loads(self.config_path.read_text(encoding="utf-8"))
        required = {
            "assurance_profile",
            "scenario_id",
            "asset_id",
            "target",
            "credential_ref",
            "identity_agent",
            "username",
            "pinned_host_key_file",
            "marker_path",
            "marker_content_sha256",
            "cleanup_required",
            "rollback_verification_required",
            "maximum_duration_seconds",
            "maximum_tool_calls",
            "isolated_lab_ready",
        }
        if (
            set(value) != required
            or value.get("assurance_profile") != "poc"
            or value.get("scenario_id") != SCENARIO_ID
        ):
            raise ValueError("scenario_configuration_invalid")
        if value.get("asset_id") != "asset:winsrv2025-01":
            raise ValueError("scenario_asset_unapproved")
        if value.get("identity_agent") != IDENTITY_AGENT_PATH:
            raise ValueError("scenario_identity_agent_invalid")
        address = ipaddress.ip_address(value["target"])
        reachability = (
            load_protected_json(self.reachability_path)
            if self.require_protected_config
            else json.loads(self.reachability_path.read_text(encoding="utf-8"))
        )
        if (
            set(reachability) != {"asset_id", "target", "port"}
            or reachability.get("asset_id") != value.get("asset_id")
            or reachability.get("target") != value.get("target")
            or reachability.get("port") != 22
        ):
            raise ValueError("scenario_registered_target_binding_invalid")
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise ValueError("scenario_target_invalid")
        if (
            value.get("marker_path") != MARKER_PATH
            or value.get("marker_content_sha256") != MARKER_DIGEST
        ):
            raise ValueError("scenario_marker_invalid")
        if (
            value.get("cleanup_required") is not True
            or value.get("rollback_verification_required") is not True
            or value.get("isolated_lab_ready") is not True
        ):
            raise ValueError("scenario_readiness_invalid")
        if (
            value.get("maximum_duration_seconds") != 60
            or value.get("maximum_tool_calls") != 6
        ):
            raise ValueError("scenario_limits_invalid")
        self.target_resolved = True
        return value

    def execute(self, authorization_id: object) -> dict[str, Any]:
        selected = validate_authorization_id(authorization_id, "T3-C", clock=self.clock)
        config = self._config()
        consume_authorization_id(self.nonce_db_path, selected, "T3-C")
        connector = self.connector_factory(config)
        self.credential_provider_invoked = True
        self.connector_invoked = True
        absent_preflight = created = proof_verified = cleanup_completed = (
            rollback_verified
        ) = False
        status = "create_failed"
        warning = None
        try:
            if connector.exists():
                status = "marker_preexisting"
            else:
                absent_preflight = True
                connector.create()
                created = True
                status = "proof_failed"
                try:
                    proof_verified = (
                        connector.exists() and connector.digest() == MARKER_DIGEST
                    )
                    status = "proof_failed" if not proof_verified else "succeeded"
                finally:
                    try:
                        connector.cleanup()
                        cleanup_completed = True
                    except Exception:
                        status = "cleanup_failed"
                        warning = "operator_action_required_marker_may_remain"
                    if cleanup_completed:
                        try:
                            rollback_verified = not connector.exists()
                            if not rollback_verified:
                                status = "rollback_failed"
                                warning = "operator_action_required_marker_may_remain"
                        except Exception:
                            status = "rollback_failed"
                            warning = "operator_action_required_marker_state_unknown"
                if not (proof_verified and cleanup_completed and rollback_verified):
                    status = status if status != "succeeded" else "rollback_failed"
        except Exception:
            if created and not cleanup_completed:
                warning = "operator_action_required_marker_may_remain"
            if status == "succeeded":
                status = "proof_failed"
        return {
            "schema_version": SCHEMA,
            "canonical_action": ACTION_ID,
            "scenario_id": SCENARIO_ID,
            "status": status,
            "marker_absent_preflight": absent_preflight,
            "marker_created": created,
            "proof_verified": proof_verified,
            "cleanup_completed": cleanup_completed,
            "rollback_verified": rollback_verified,
            "connector_invoked": self.connector_invoked,
            "operator_warning": warning,
        }


def register_t3c_routes(
    app, service: T3CService | None = None, *, assurance_profile: str | None = None
) -> None:
    if service is None:
        if assurance_profile != "poc":
            return
        service = T3CService()
    blueprint = Blueprint("t3c", __name__)

    @blueprint.post("/api/v1/t3c/executions")
    def execute_t3c():
        body = request.get_json(silent=True)
        if (
            not isinstance(body, dict)
            or set(body) != {"authorization_id", "canonical_action"}
            or body.get("canonical_action") != ACTION_ID
        ):
            _LOGGER.warning(
                "event=poc_scope_denied connector_invoked=false action=%s", ACTION_ID
            )
            return jsonify(
                {"error": "poc_scope_denied", "connector_invoked": False}
            ), 403
        try:
            result = service.execute(body["authorization_id"])
            return jsonify(result), 200 if result["status"] == "succeeded" else 422
        except ValueError as exc:
            code = str(exc)
            return jsonify(
                {"error": code, "connector_invoked": False}
            ), 409 if code == "authorization_replayed" else 403
        except Exception:
            return jsonify(
                {"error": "t3c_request_denied", "connector_invoked": False}
            ), 403

    app.register_blueprint(blueprint)
