"""Explicit unsigned PoC routes backed only by protected canonical configuration."""

from __future__ import annotations

import grp
import ipaddress
import json
import logging
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, request

from hexstrike_t3_authorization import (
    consume_authorization_id,
    validate_authorization_id,
)
from hexstrike_t3_reachability import ASSET_ID, PORT, target_binding
from hexstrike_t3a import OPERATION_ID as T3A_OPERATION_ID
from hexstrike_t3a import T3AService
from hexstrike_t3b import (
    DEFINITION_DIGESTS,
    OPERATION_ID as T3B_OPERATION_ID,
    PROFILE_ID as T3B_PROFILE,
    REGISTRY_DIGEST,
    SCRIPTS,
    STAGE as T3B_STAGE,
    T3BService,
)

PROFILE = "poc"
CREDENTIAL_REF = "credential:ssh-winsrv2025-01"
_HOST_KEY = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$")
_LOGGER = logging.getLogger("hexstrike.t3.poc")


def _protected_json(path: Path) -> dict[str, Any]:
    info = path.stat()
    if (
        info.st_uid != 0
        or grp.getgrgid(info.st_gid).gr_name != "hexstrike"
        or stat.S_IMODE(info.st_mode) != 0o640
    ):
        raise ValueError("poc_configuration_not_protected")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("poc_configuration_invalid")
    return value


class T3PocService:
    """Resolve every executable field from protected files and consume once."""

    def __init__(
        self,
        *,
        reachability_path: Path = Path("/etc/hexstrike/t3-reachability.json"),
        runtime_path: Path = Path("/etc/hexstrike/t3-poc-runtime.json"),
        target_matrix_path: Path = Path("/etc/hexstrike/job-targets.json"),
        credential_config_path: Path = Path("/etc/hexstrike/t3a-credentials.json"),
        authorization_db_path: Path = Path(
            "/var/lib/hexstrike/spent-poc-authorizations.sqlite3"
        ),
        kill_switch_path: Path = Path("/run/hexstrike/KILL"),
        t3a_runner=None,
        t3b_runner=None,
        protected: bool = True,
        clock=time.time,
    ):
        loader = (
            _protected_json if protected else lambda path: json.loads(path.read_text())
        )
        reachability = loader(reachability_path)
        runtime = loader(runtime_path)
        if (
            set(reachability) != {"asset_id", "target", "port"}
            or reachability.get("asset_id") != ASSET_ID
            or reachability.get("port") != PORT
        ):
            raise ValueError("poc_reachability_configuration_invalid")
        target = str(reachability.get("target", ""))
        ipaddress.IPv4Address(target)
        if (
            set(runtime)
            != {
                "assurance_profile",
                "asset_id",
                "target_binding",
                "pinned_host_key",
            }
            or runtime.get("assurance_profile") != PROFILE
            or runtime.get("asset_id") != ASSET_ID
            or runtime.get("target_binding") != target_binding(ASSET_ID, target, PORT)
            or not _HOST_KEY.fullmatch(str(runtime.get("pinned_host_key", "")))
        ):
            raise ValueError("poc_runtime_configuration_invalid")
        matrix = loader(target_matrix_path)
        if matrix != {"allowed_targets": [f"{target}/32"]}:
            raise ValueError("poc_target_matrix_invalid")
        self.target = target
        self.pinned_host_key = str(runtime["pinned_host_key"])
        self.authorization_db_path = authorization_db_path
        self.clock = clock
        self.t3a = T3AService(
            permit_secret=b"",
            target_matrix_path=target_matrix_path,
            credential_config_path=credential_config_path,
            nonce_db_path=authorization_db_path,
            kill_switch_path=kill_switch_path,
            runner=t3a_runner,
            allow_unsigned_poc=True,
        )
        self.t3b = T3BService(
            permit_secret=b"",
            target_matrix_path=target_matrix_path,
            credential_config_path=credential_config_path,
            nonce_db_path=authorization_db_path,
            kill_switch_path=kill_switch_path,
            runner=t3b_runner,
            allow_unsigned_poc=True,
        )

    def execute_t3a(self, authorization_id: object) -> dict[str, Any]:
        selected = validate_authorization_id(authorization_id, "T3-A", clock=self.clock)
        claims = {
            "permit_id": selected,
            "asset_id": ASSET_ID,
            "target": self.target,
            "port": PORT,
            "credential_ref": CREDENTIAL_REF,
            "pinned_host_key": self.pinned_host_key,
        }
        consume_authorization_id(self.authorization_db_path, selected, "T3-A")
        result = self.t3a.execute(claims)
        result["schema_version"] = "hexstrike-t3a-poc-result/v1"
        result["authorization_id"] = result.pop("permit_id")
        return result

    def execute_t3b(self, authorization_id: object) -> dict[str, Any]:
        selected = validate_authorization_id(authorization_id, "T3-B", clock=self.clock)
        claims = {
            "permit_id": selected,
            "asset_id": ASSET_ID,
            "profile_id": T3B_PROFILE,
            "stage": T3B_STAGE,
            "target": self.target,
            "port": PORT,
            "credential_ref": CREDENTIAL_REF,
            "pinned_host_key": self.pinned_host_key,
            "command_ids": list(SCRIPTS),
            "registry_digest": REGISTRY_DIGEST,
            "definition_digests": [DEFINITION_DIGESTS[item] for item in SCRIPTS],
            "limits": {
                "max_commands": 5,
                "max_sessions": 1,
                "per_command_timeout_seconds": 15,
                "total_timeout_seconds": 60,
                "stdout_limit": 16_384,
                "stderr_limit": 4_096,
                "total_output_limit": 50_000,
            },
            "started_at": int(time.time()),
        }
        consume_authorization_id(self.authorization_db_path, selected, "T3-B")
        result = self.t3b.execute(claims)
        result["schema_version"] = "hexstrike-t3b-poc-result/v1"
        result["authorization_id"] = result.pop("permit_id")
        return result


def register_t3_poc_routes(
    app,
    service: T3PocService | None = None,
    *,
    assurance_profile: str | None = None,
) -> None:
    if service is None:
        if assurance_profile != PROFILE:
            return
        service = T3PocService(
            reachability_path=Path(
                os.environ.get(
                    "HEXSTRIKE_T3_REACHABILITY_CONFIG",
                    "/etc/hexstrike/t3-reachability.json",
                )
            ),
            runtime_path=Path(
                os.environ.get(
                    "HEXSTRIKE_T3_POC_RUNTIME_CONFIG",
                    "/etc/hexstrike/t3-poc-runtime.json",
                )
            ),
        )
    blueprint = Blueprint("hexstrike_t3_poc", __name__)

    def valid_body(action: str) -> tuple[dict[str, Any] | None, Any | None]:
        body = request.get_json(silent=True)
        if (
            not isinstance(body, dict)
            or set(body) != {"authorization_id", "canonical_action"}
            or body.get("canonical_action") != action
        ):
            _LOGGER.warning(
                "event=poc_scope_denied connector_invoked=false action=%s",
                action,
            )
            return None, (jsonify({"error": "poc_scope_denied"}), 403)
        return body, None

    @blueprint.post("/api/v1/t3a/poc-executions")
    def execute_t3a_poc():
        body, error = valid_body(T3A_OPERATION_ID)
        if error:
            return error
        try:
            result = service.execute_t3a(body["authorization_id"])
            return jsonify(result), 200 if result["status"] == "completed" else 422
        except ValueError as exc:
            code = str(exc)
            return (
                jsonify({"error": code}),
                409 if code == "authorization_replayed" else 403,
            )
        except Exception:
            return jsonify({"error": "t3a_poc_execution_failed"}), 500

    @blueprint.post("/api/v1/t3b/poc-executions")
    def execute_t3b_poc():
        body, error = valid_body(T3B_OPERATION_ID)
        if error:
            return error
        try:
            result = service.execute_t3b(body["authorization_id"])
            return jsonify(result), 200 if result["status"] == "verified" else 422
        except ValueError as exc:
            code = str(exc)
            return (
                jsonify({"error": code}),
                409 if code == "authorization_replayed" else 403,
            )
        except Exception:
            return jsonify({"error": "t3b_poc_execution_failed"}), 500

    app.register_blueprint(blueprint)
