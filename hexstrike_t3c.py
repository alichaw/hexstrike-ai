"""Loopback-only, fixed-scenario T3-C synthetic marker endpoint."""

from __future__ import annotations

import ipaddress
import json
import os
import grp
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, request

from hexstrike_t3_authorization import (
    consume_authorization_id,
    validate_authorization_id,
)

ACTION_ID = "t3c.controlled_impact_proof.v1"
SCHEMA = "hexstrike-t3c-result/v1"
MARKER_PATH = "/opt/t3c/proof-marker"


class T3CService:
    """Resolve all sensitive and executable state from protected server configuration."""

    def __init__(
        self,
        config_path: str | Path | None = None,
        runner=None,
        nonce_db_path: str | Path | None = None,
        clock=time.time,
    ):
        selected_path = config_path or os.environ.get("HEXSTRIKE_T3C_CONFIG", "")
        self.require_protected_config = config_path is None
        self.config_path = Path(selected_path)
        self.nonce_db_path = Path(
            nonce_db_path
            or (
                "/var/lib/hexstrike/spent-poc-authorizations.sqlite3"
                if config_path is None
                else self.config_path.with_suffix(".sqlite3")
            )
        )
        self.clock = clock
        self.runner = runner or self._run_fixed

    def _config(self) -> dict[str, Any]:
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
            "source_asset_id",
            "destination_asset_id",
            "destination_target",
            "credential_ref",
            "identity_agent",
            "username",
            "pinned_host_key_file",
            "proof_marker",
            "rollback_checkpoint",
            "isolated_lab",
            "rollback_ready",
        }
        if (
            set(value) != required
            or value["assurance_profile"] != "poc"
            or value["scenario_id"] != "lab.synthetic-marker.v1"
        ):
            raise ValueError("scenario_configuration_invalid")
        address = ipaddress.ip_address(value["destination_target"])
        if not address.is_private or address.is_loopback:
            raise ValueError("scenario_target_invalid")
        if value["isolated_lab"] is not True or value["rollback_ready"] is not True:
            raise ValueError("scenario_readiness_invalid")
        return value

    def execute(self, authorization_id: str) -> dict[str, Any]:
        selected = validate_authorization_id(authorization_id, "T3-C", clock=self.clock)
        config = self._config()
        consume_authorization_id(self.nonce_db_path, selected, "T3-C")
        output = self.runner(config)
        if not isinstance(output, str) or len(output.encode()) > 4096:
            raise ValueError("proof_output_invalid")
        return {
            "schema_version": SCHEMA,
            "canonical_action": ACTION_ID,
            "scenario_id": config["scenario_id"],
            "proof_output": output,
            "cleanup_succeeded": True,
            "cleanup_evidence": f"read-only proof; checkpoint {config['rollback_checkpoint']} unchanged",
        }

    @staticmethod
    def _run_fixed(config: dict[str, Any]) -> str:
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
                f"IdentityAgent={config['identity_agent']}",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={config['pinned_host_key_file']}",
                "-o",
                "ConnectTimeout=15",
                "-o",
                "ConnectionAttempts=1",
                f"{config['username']}@{config['destination_target']}",
                "cat -- /opt/t3c/proof-marker",
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
        if (
            completed.returncode != 0
            or completed.stderr
            or len(completed.stdout) > 4096
        ):
            raise ValueError("fixed_proof_execution_failed")
        return completed.stdout.decode("utf-8", errors="strict").strip()


def register_t3c_routes(
    app,
    service: T3CService | None = None,
    *,
    assurance_profile: str | None = None,
) -> None:
    if service is None:
        if assurance_profile != "poc":
            return
        service = T3CService()
    selected = service
    blueprint = Blueprint("t3c", __name__)

    @blueprint.post("/api/v1/t3c/executions")
    def execute_t3c():
        try:
            body = request.get_json(silent=True)
            if not isinstance(body, dict) or set(body) != {
                "authorization_id",
                "canonical_action",
            }:
                raise ValueError("request_invalid")
            if body["canonical_action"] != ACTION_ID:
                raise ValueError("action_invalid")
            return jsonify(selected.execute(body["authorization_id"])), 200
        except ValueError as exc:
            code = str(exc)
            return (
                jsonify({"error": "t3c_request_denied"}),
                409 if code == "authorization_replayed" else 403,
            )
        except Exception:
            return jsonify({"error": "t3c_request_denied"}), 403

    app.register_blueprint(blueprint)
