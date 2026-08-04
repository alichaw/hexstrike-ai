"""One fail-closed T3 path for the narrow Windows SSH research PoC."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from uuid import UUID, uuid4

from flask import Blueprint, jsonify, request

SCHEMA_VERSION = "hexstrike-t3-result/v1"
EVIDENCE_SCHEMA_VERSION = "hexstrike-t3-evidence/v1"
AUDIT_SCHEMA_VERSION = "hexstrike-t3-audit/v1"
RUNTIME_SCHEMA_VERSION = "hexstrike-t3-runtime/v1"
ASSET_ID = "asset:winsrv2025-01"
REACHABILITY_ACTION = "t3a.ssh22_reachability.v1"
IDENTITY_ACTION = "windows.ssh.readonly_identity.v1"
_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")
_HOST_KEY = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$")
_SENSITIVE = re.compile(
    r"(?i)(password|private[_-]?key|authorization|secret|token|credential|ntlm|"
    r"kerberos|connection[_-]?string)"
)


@dataclass(frozen=True)
class Action:
    action_id: str
    maximum_tool_calls: int
    maximum_duration_seconds: int
    prerequisites: tuple[str, ...] = ()


_ACTION_ROWS = (
    Action(REACHABILITY_ACTION, 1, 5),
    Action(IDENTITY_ACTION, 3, 45, (REACHABILITY_ACTION,)),
)
ACTIONS = {item.action_id: item for item in _ACTION_ROWS}

FIXED_WINDOWS_COMMANDS = (
    ("effective_username", ("whoami",)),
    ("computer_hostname", ("hostname",)),
    ("os_identification", ("cmd.exe", "/d", "/c", "ver")),
)


def canonical_digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def authorization_digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SENSITIVE.search(str(key)) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)(password|secret|token)=\S+", r"\1=[REDACTED]", value)
        return value[:4096]
    return value


def load_runtime(path: str | Path, *, owner_uid: int | None = None) -> dict[str, Any]:
    selected = Path(path)
    if selected.is_symlink():
        raise ValueError("runtime_invalid")
    descriptor = -1
    try:
        descriptor = os.open(selected, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(descriptor)
        expected_uid = os.geteuid() if owner_uid is None else owner_uid
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("runtime_invalid")
        with os.fdopen(descriptor, encoding="utf-8") as handle:
            descriptor = -1
            value = json.load(handle)
        return value
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("runtime_invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class LiveWindowsSshAdapter:
    """The only live adapter: TCP/22 and three fixed read-only SSH commands."""

    execution_available = True
    maximum_output_bytes = 4096

    def __init__(self, *, connector=None, process=None):
        self.connector = connector or self._connect
        self.process = process or self._run

    @staticmethod
    def _connect(target: str, port: int, timeout: int) -> None:
        connection = socket.create_connection((target, port), timeout=timeout)
        connection.close()

    @staticmethod
    def _run(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def __call__(
        self, action: Action, runtime: dict[str, Any], kill_check
    ) -> dict[str, Any]:
        asset = runtime["assets"][ASSET_ID]
        if action.action_id == REACHABILITY_ACTION:
            kill_check()
            try:
                self.connector(asset["target"], 22, 5)
            except Exception:
                return {
                    "status": "failed",
                    "tool_calls": 1,
                    "evidence": {"reachability": "unreachable"},
                }
            return {
                "status": "completed",
                "tool_calls": 1,
                "evidence": {"reachability": "reachable"},
            }
        if action.action_id != IDENTITY_ACTION:
            raise ValueError("unknown_action")
        values: dict[str, str] = {}
        with tempfile.TemporaryDirectory(prefix="hexstrike-t3-") as temporary:
            known_hosts = Path(temporary) / "known_hosts"
            known_hosts.write_text(
                f"{asset['target']} {asset['pinned_host_key']}\n", encoding="utf-8"
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
                f"IdentityAgent={asset['identity_agent']}",
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
                asset["username"],
                asset["target"],
            ]
            for field, command in FIXED_WINDOWS_COMMANDS:
                kill_check()
                try:
                    completed = self.process([*base, *command], 15)
                except Exception:
                    return {
                        "status": "failed",
                        "tool_calls": len(values) + 1,
                        "evidence": {"failure": "ssh_execution_failed"},
                    }
                output = completed.stdout.encode(errors="replace")
                error = completed.stderr.encode(errors="replace")
                if (
                    completed.returncode != 0
                    or len(output) > self.maximum_output_bytes
                    or len(error) > self.maximum_output_bytes
                ):
                    return {
                        "status": "failed",
                        "tool_calls": len(values) + 1,
                        "evidence": {"failure": "ssh_execution_failed"},
                    }
                normalized = " ".join(completed.stdout.split())[:512]
                if not normalized:
                    return {
                        "status": "failed",
                        "tool_calls": len(values) + 1,
                        "evidence": {"failure": "ssh_execution_failed"},
                    }
                values[field] = normalized
        return {
            "status": "completed",
            "tool_calls": 3,
            "evidence": {
                "reachability": "prerequisite_verified",
                "host_key_verification": "strict_pinned_ed25519",
                "authentication": "succeeded",
                "fixed_query_summary": values,
            },
        }


class FakeWindowsSshAdapter(LiveWindowsSshAdapter):
    offline_fake = True


class UnifiedT3Service:
    def __init__(self, runtime: dict[str, Any], *, adapter: Callable, clock=time.time):
        required = {
            "schema_version",
            "runtime_revision",
            "assets",
            "approval_database",
            "evidence_root",
            "kill_switch_file",
            "action_policy",
        }
        if (
            set(runtime) != required
            or runtime.get("schema_version") != RUNTIME_SCHEMA_VERSION
        ):
            raise ValueError("runtime_invalid")
        policy = runtime.get("action_policy")
        assets = runtime.get("assets")
        if (
            not isinstance(policy, dict)
            or set(policy) != {"enabled_action_ids"}
            or policy["enabled_action_ids"] != list(ACTIONS)
        ):
            raise ValueError("runtime_invalid")
        if not isinstance(assets, dict) or set(assets) != {ASSET_ID}:
            raise ValueError("runtime_invalid")
        asset = assets[ASSET_ID]
        if not isinstance(asset, dict) or set(asset) != {
            "target",
            "port",
            "credential_ref",
            "username",
            "identity_agent",
            "pinned_host_key",
        }:
            raise ValueError("runtime_invalid")
        try:
            UUID(str(runtime["runtime_revision"]))
            ipaddress.IPv4Address(asset["target"])
        except (ValueError, TypeError):
            raise ValueError("runtime_invalid") from None
        if (
            asset["port"] != 22
            or not _REFERENCE.fullmatch(str(asset["credential_ref"]))
            or not _USERNAME.fullmatch(str(asset["username"]))
            or not Path(asset["identity_agent"]).is_absolute()
            or not _HOST_KEY.fullmatch(str(asset["pinned_host_key"]))
        ):
            raise ValueError("runtime_invalid")
        for field in ("approval_database", "evidence_root", "kill_switch_file"):
            if (
                not isinstance(runtime[field], str)
                or not Path(runtime[field]).is_absolute()
            ):
                raise ValueError("runtime_invalid")
        self.runtime = runtime
        self.runtime_digest = canonical_digest(runtime)
        self.adapter = adapter
        self.clock = clock

    def _validate_state_paths(self) -> None:
        database = Path(self.runtime["approval_database"])
        info = database.stat()
        if (
            database.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("approval_database_invalid")
        root = Path(self.runtime["evidence_root"])
        if root.is_symlink():
            raise ValueError("evidence_root_invalid")
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if (
            not stat.S_ISDIR(root.stat().st_mode)
            or root.stat().st_uid != os.geteuid()
            or stat.S_IMODE(root.stat().st_mode) != 0o700
        ):
            raise ValueError("evidence_root_invalid")

    def _kill_check(self) -> None:
        selected = Path(self.runtime["kill_switch_file"])
        try:
            if selected.is_symlink() or selected.exists():
                raise ValueError("kill_switch_engaged")
        except OSError as exc:
            raise ValueError("kill_switch_state_invalid") from exc

    def _consume(self, authorization_id: str, action_id: str, now: int) -> None:
        try:
            with sqlite3.connect(
                self.runtime["approval_database"],
                timeout=5,
                isolation_level="IMMEDIATE",
            ) as database:
                database.execute("BEGIN IMMEDIATE")
                cursor = database.execute(
                    "UPDATE approvals SET state='consumed', consumed_at=? WHERE authorization_id_digest=? "
                    "AND state='pending' AND action_id=? AND asset_id=? AND runtime_revision=? "
                    "AND runtime_digest=? AND issued_at<=? AND expires_at>?",
                    (
                        now,
                        authorization_digest(authorization_id),
                        action_id,
                        ASSET_ID,
                        str(self.runtime["runtime_revision"]),
                        self.runtime_digest,
                        now,
                        now,
                    ),
                )
                if cursor.rowcount != 1:
                    database.rollback()
                    raise ValueError("authorization_rejected")
                database.commit()
        except sqlite3.Error:
            raise ValueError("authorization_rejected") from None

    def _prerequisites(self, action: Action) -> None:
        root = Path(self.runtime["evidence_root"])
        for prerequisite in action.prerequisites:
            matches = list(root.glob(f"*/{canonical_digest(prerequisite)}.json"))
            if not matches:
                raise ValueError("prerequisite_not_satisfied")
            document = json.loads(matches[-1].read_text(encoding="utf-8"))
            seal = document.pop("seal", None)
            if (
                document.get("action_id") != prerequisite
                or document.get("runtime_digest") != self.runtime_digest
                or document.get("status") != "completed"
                or seal != canonical_digest(document)
            ):
                raise ValueError("prerequisite_not_satisfied")

    def _write_audit(
        self, action_id: str, decision: str, authorization_id: str | None = None
    ) -> str:
        root = Path(self.runtime["evidence_root"]) / "audit"
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        document = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "event_id": str(uuid4()),
            "action_id": action_id,
            "asset_id": ASSET_ID,
            "policy_decision": decision,
            "runtime_digest": self.runtime_digest,
            "authorization_id_digest": authorization_digest(authorization_id)
            if authorization_id
            else None,
            "recorded_at": int(self.clock()),
        }
        document["seal"] = canonical_digest(document)
        path = root / f"{document['event_id']}.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, sort_keys=True, separators=(",", ":"))
        return str(path.relative_to(self.runtime["evidence_root"]))

    def _write_result(
        self, authorization_id: str, action: Action, raw: dict[str, Any]
    ) -> dict[str, Any]:
        digest = authorization_digest(authorization_id)
        directory = Path(self.runtime["evidence_root"]) / digest
        directory.mkdir(parents=True, mode=0o700, exist_ok=False)
        evidence = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "authorization_id_digest": digest,
            "action_id": action.action_id,
            "asset_id": ASSET_ID,
            "runtime_digest": self.runtime_digest,
            "status": raw["status"],
            "tool_calls": raw["tool_calls"],
            "evidence": _redact(raw["evidence"]),
        }
        evidence["seal"] = canonical_digest(evidence)
        path = directory / f"{canonical_digest(action.action_id)}.json"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(evidence, handle, sort_keys=True, separators=(",", ":"))
        return {
            "schema_version": SCHEMA_VERSION,
            "authorization_id_digest": digest,
            "action_id": action.action_id,
            "status": raw["status"],
            "runtime_digest": self.runtime_digest,
            "executor_family": "WINDOWS_SSH",
            "tool_calls": raw["tool_calls"],
            "evidence_ref": str(path.relative_to(self.runtime["evidence_root"])),
            "evidence_digest": evidence["seal"],
        }

    def execute(self, authorization_id: str, action_id: str) -> dict[str, Any]:
        if not isinstance(authorization_id, str) or not _ID.fullmatch(authorization_id):
            raise ValueError("authorization_invalid")
        action = ACTIONS.get(action_id)
        if action is None:
            raise ValueError("unknown_action")
        if action_id not in self.runtime["action_policy"]["enabled_action_ids"]:
            raise ValueError("action_not_enabled")
        self._validate_state_paths()
        try:
            self._kill_check()
        except ValueError:
            self._write_audit(action_id, "kill_switch_denied", authorization_id)
            raise
        self._prerequisites(action)
        digest = authorization_digest(authorization_id)
        if (Path(self.runtime["evidence_root"]) / digest).exists():
            self._write_audit(action_id, "replay_denied", authorization_id)
            raise ValueError("authorization_rejected")
        try:
            self._consume(authorization_id, action_id, int(self.clock()))
        except ValueError:
            self._write_audit(action_id, "approval_denied", authorization_id)
            raise
        started_at = int(self.clock())
        started = time.monotonic()
        try:
            raw = self.adapter(action, self.runtime, self._kill_check)
        except Exception:
            raw = {
                "status": "failed",
                "tool_calls": 0,
                "evidence": {"failure": "execution_failed"},
            }
        if time.monotonic() - started > action.maximum_duration_seconds:
            raw = {
                "status": "failed",
                "tool_calls": 0,
                "evidence": {"failure": "execution_timeout"},
            }
        if (
            not isinstance(raw, dict)
            or set(raw) != {"status", "tool_calls", "evidence"}
            or raw["status"] not in {"completed", "failed"}
            or not isinstance(raw["tool_calls"], int)
            or not 0 <= raw["tool_calls"] <= action.maximum_tool_calls
        ):
            raw = {
                "status": "failed",
                "tool_calls": 0,
                "evidence": {"failure": "execution_result_invalid"},
            }
        raw["evidence"] = {
            "action_requested": action_id,
            "canonical_action": action.action_id,
            "asset_id": ASSET_ID,
            "policy_decision": "allowed",
            "approval_decision": "consumed",
            "runtime_revision": str(self.runtime["runtime_revision"]),
            "started_at": started_at,
            "ended_at": int(self.clock()),
            **raw["evidence"],
        }
        return self._write_result(authorization_id, action, raw)


def build_production_unified_service() -> UnifiedT3Service:
    path = Path(
        os.environ.get(
            "HEXSTRIKE_T3_UNIFIED_RUNTIME_CONFIG",
            "/etc/hexstrike/t3-unified-runtime.json",
        )
    )
    return UnifiedT3Service(load_runtime(path), adapter=LiveWindowsSshAdapter())


def register_unified_t3_route(
    app,
    service: UnifiedT3Service | None = None,
    *,
    service_factory=build_production_unified_service,
) -> None:
    if "hexstrike_t3_execution" in app.blueprints:
        return
    blueprint = Blueprint("hexstrike_t3_execution", __name__)

    @blueprint.post("/api/v1/t3/executions")
    def execute():
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or set(body) != {
            "authorization_id",
            "canonical_action",
        }:
            return jsonify({"error": "request_schema_invalid"}), 400
        try:
            result = (service or service_factory()).execute(
                body["authorization_id"], body["canonical_action"]
            )
            return jsonify(result), 200 if result["status"] == "completed" else 422
        except ValueError as exc:
            allowed = {
                "authorization_invalid",
                "authorization_rejected",
                "unknown_action",
                "action_not_enabled",
                "approval_database_invalid",
                "evidence_root_invalid",
                "kill_switch_engaged",
                "kill_switch_state_invalid",
                "prerequisite_not_satisfied",
            }
            code = str(exc) if str(exc) in allowed else "execution_denied"
            return jsonify(
                {"error": code}
            ), 409 if code == "authorization_rejected" else 403

    app.register_blueprint(blueprint)


def register_production_unified_t3_route(app, *, assurance_profile: str) -> None:
    if assurance_profile == "poc":
        register_unified_t3_route(app)
