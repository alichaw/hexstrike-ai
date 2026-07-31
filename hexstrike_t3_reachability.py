"""Fixed TCP/22 reachability endpoint for canonical T3 investigation state."""

from __future__ import annotations

import grp
import hashlib
import ipaddress
import json
import os
import socket
import stat
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, request

ACTION_ID = "t3a.ssh22_reachability.v1"
ASSET_ID = "asset:winsrv2025-01"
PORT = 22
SCHEMA = "hexstrike-t3-ssh-reachability/v1"
TIMEOUT_SECONDS = 5


def target_binding(asset_id: str, target: str, port: int) -> str:
    return hashlib.sha256(f"{asset_id}\0{target}\0{port}".encode()).hexdigest()


class T3SshReachabilityService:
    """Resolve the sole target from protected server state and connect only to TCP/22."""

    def __init__(self, config_path: str | Path | None = None, connector=None):
        self.require_protected_config = config_path is None
        self.config_path = Path(
            config_path
            or os.environ.get(
                "HEXSTRIKE_T3_REACHABILITY_CONFIG",
                "/etc/hexstrike/t3-reachability.json",
            )
        )
        self.connector = connector or self._connect

    def _config(self) -> dict[str, Any]:
        if self.require_protected_config:
            info = self.config_path.stat()
            if (
                info.st_uid != 0
                or grp.getgrgid(info.st_gid).gr_name != "hexstrike"
                or stat.S_IMODE(info.st_mode) != 0o640
            ):
                raise ValueError("reachability_configuration_not_protected")
        value = json.loads(self.config_path.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or set(value) != {"asset_id", "target", "port"}
            or value.get("asset_id") != ASSET_ID
            or value.get("port") != PORT
        ):
            raise ValueError("reachability_configuration_invalid")
        ipaddress.ip_address(value["target"])
        return value

    def execute(self, asset_id: str) -> dict[str, Any]:
        if asset_id != ASSET_ID:
            raise ValueError("asset_not_permitted")
        config = self._config()
        try:
            state = self.connector(config["target"], PORT)
        except Exception:
            state = "error"
        if state not in {"reachable", "unreachable", "error"}:
            state = "error"
        return {
            "schema_version": SCHEMA,
            "action_id": ACTION_ID,
            "asset_id": ASSET_ID,
            "port": PORT,
            "protocol": "tcp",
            "service": "ssh",
            "state": state,
            "target_binding": target_binding(ASSET_ID, config["target"], PORT),
        }

    @staticmethod
    def _connect(target: str, port: int) -> str:
        try:
            connection = socket.create_connection(
                (target, port), timeout=TIMEOUT_SECONDS
            )
        except (ConnectionRefusedError, TimeoutError, socket.timeout):
            return "unreachable"
        except OSError:
            return "error"
        connection.close()
        return "reachable"


def register_t3_reachability_routes(
    app, service: T3SshReachabilityService | None = None
) -> None:
    selected = service or T3SshReachabilityService()
    blueprint = Blueprint("t3_ssh_reachability", __name__)

    @blueprint.post("/api/v1/t3/ssh-reachability")
    def ssh_reachability():
        try:
            body = request.get_json(silent=True)
            if (
                not isinstance(body, dict)
                or set(body) != {"action_id", "asset_id"}
                or body.get("action_id") != ACTION_ID
            ):
                raise ValueError("request_invalid")
            return jsonify(selected.execute(body["asset_id"])), 200
        except Exception:
            return jsonify({"error": "t3_ssh_reachability_denied"}), 403

    app.register_blueprint(blueprint)
