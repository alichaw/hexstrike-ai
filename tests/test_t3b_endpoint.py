import base64
import hashlib
import hmac
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hexstrike_t3b import (  # noqa: E402
    DEFINITION_DIGESTS,
    OPERATION_ID,
    PERMIT_SCHEMA,
    PROFILE_ID,
    REGISTRY_DIGEST,
    RESULT_SCHEMA,
    SCRIPTS,
    STAGE,
    T3BService,
    register_t3b_routes,
)

SECRET = b"synthetic-t3b-permit-secret-32bytes"
TARGET = "192.0.2.25"
HOST_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4"
)


def encode(value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    def b64(item):
        return base64.urlsafe_b64encode(item).decode().rstrip("=")

    return f"{b64(payload)}.{b64(hmac.new(SECRET, payload, hashlib.sha256).digest())}"


def claims(**updates):
    now = int(time.time())
    value = {
        "schema_version": PERMIT_SCHEMA,
        "permit_id": "permit-b",
        "nonce": "nonce-b",
        "issued_at": now,
        "expires_at": now + 60,
        "asset_id": "asset:winsrv2025-01",
        "profile_id": PROFILE_ID,
        "stage": STAGE,
        "operation_id": OPERATION_ID,
        "target": TARGET,
        "port": 22,
        "credential_ref": "credential:ssh-winsrv2025-01",
        "pinned_host_key": HOST_KEY,
        "prerequisite_run_id": "sealed-t3a-run",
        "approval_fingerprint": "a" * 64,
        "runtime_binding_fingerprint": "b" * 64,
        "command_ids": list(SCRIPTS),
        "registry_digest": REGISTRY_DIGEST,
        "definition_digests": [DEFINITION_DIGESTS[item] for item in SCRIPTS],
        "limits": {
            "max_commands": 5,
            "max_sessions": 1,
            "per_command_timeout_seconds": 15,
            "total_timeout_seconds": 60,
            "stdout_limit": 16384,
            "stderr_limit": 4096,
            "total_output_limit": 50000,
        },
        "result_schema": RESULT_SCHEMA,
    }
    value.update(updates)
    return value


@pytest.fixture
def service(tmp_path):
    calls = {"resolve": 0, "run": 0}

    def runner(bound, credential):
        calls["run"] += 1
        return [
            {
                "action_id": item,
                "definition_digest": DEFINITION_DIGESTS[item],
                "started_at": "2026-07-30T00:00:00+00:00",
                "completed_at": "2026-07-30T00:00:01+00:00",
                "duration_seconds": 1.0,
                "exit_status": 0,
                "stdout": "{}",
                "stderr": "",
                "stdout_original_bytes": 2,
                "stdout_retained_bytes": 2,
                "stderr_original_bytes": 0,
                "stderr_retained_bytes": 0,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "stdout_decoding_errors": False,
                "stderr_decoding_errors": False,
            }
            for item in SCRIPTS
        ]

    selected = T3BService(
        permit_secret=SECRET,
        target_matrix_path=tmp_path / "matrix",
        credential_config_path=tmp_path / "credentials",
        nonce_db_path=tmp_path / "nonces.sqlite3",
        runner=runner,
    )
    selected.target_allowed = lambda target: target == TARGET

    def resolve(ref, asset):
        calls["resolve"] += 1
        return {"username": "poc_websvc", "identity_agent": "/run/fake.sock"}

    selected.resolve_credential = resolve
    selected.calls = calls
    return selected


def client(service):
    app = Flask(__name__)
    register_t3b_routes(app, service)
    return app.test_client()


@pytest.mark.parametrize(
    "mutation",
    [
        {"asset_id": "other"},
        {"profile_id": "other"},
        {"operation_id": "other"},
        {"target": "192.0.2.26"},
        {"port": 2222},
        {"credential_ref": "credential:other"},
        {"prerequisite_run_id": ""},
        {"approval_fingerprint": ""},
        {"command_ids": ["windows_os_version"]},
        {"command_ids": list(reversed(SCRIPTS))},
        {"command_ids": [*SCRIPTS, "extra"]},
        {"registry_digest": "c" * 64},
        {"pinned_host_key": ""},
        {"limits": {"max_commands": 6, "max_sessions": 1}},
    ],
)
def test_invalid_permit_binding_is_precredential(service, mutation):
    response = client(service).post(
        "/api/v1/t3b/executions", json={"permit": encode(claims(**mutation))}
    )
    assert response.status_code in {401, 403}
    assert service.calls == {"resolve": 0, "run": 0}


def test_missing_expired_target_denial_and_replay(service):
    selected = client(service)
    assert selected.post("/api/v1/t3b/executions", json={}).status_code == 401
    expired = encode(claims(issued_at=1, expires_at=2))
    assert (
        selected.post("/api/v1/t3b/executions", json={"permit": expired}).status_code
        == 401
    )
    service.target_allowed = lambda target: False
    assert (
        selected.post(
            "/api/v1/t3b/executions", json={"permit": encode(claims())}
        ).status_code
        == 403
    )
    assert service.calls == {"resolve": 0, "run": 0}

    service.target_allowed = lambda target: True
    token = encode(claims())
    assert (
        selected.post("/api/v1/t3b/executions", json={"permit": token}).status_code
        == 200
    )
    assert (
        selected.post("/api/v1/t3b/executions", json={"permit": token}).status_code
        == 409
    )
    assert service.calls == {"resolve": 1, "run": 1}


def test_invalid_signature_and_kill_switch_are_precredential(service, tmp_path):
    token = encode(claims())
    payload, signature = token.split(".")
    changed = ("A" if signature[0] != "A" else "B") + signature[1:]
    assert (
        client(service)
        .post("/api/v1/t3b/executions", json={"permit": f"{payload}.{changed}"})
        .status_code
        == 401
    )
    assert service.calls == {"resolve": 0, "run": 0}

    kill = tmp_path / "KILL"
    kill.touch()
    service.kill_switch_path = kill
    assert (
        client(service)
        .post("/api/v1/t3b/executions", json={"permit": encode(claims())})
        .status_code
        == 401
    )
    assert service.calls == {"resolve": 0, "run": 0}


def test_concurrent_replay_admits_one(service):
    bound = service.verify(encode(claims()))

    def admit(_):
        try:
            service.consume(bound["nonce"], bound["permit_id"])
            return True
        except (ValueError, OSError):
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(admit, range(16)))
    assert outcomes.count(True) == 1
