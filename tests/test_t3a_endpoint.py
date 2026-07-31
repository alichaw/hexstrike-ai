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
from hexstrike_t3a import (  # noqa: E402
    COMMAND_IDS,
    OPERATION_ID,
    PERMIT_SCHEMA,
    REGISTRY_DIGEST,
    RESULT_SCHEMA,
    T3AService,
    register_t3a_routes,
)

SECRET = b"synthetic-execution-permit-secret-32bytes"
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
        "permit_id": "permit-1",
        "nonce": "nonce-1",
        "issued_at": now,
        "expires_at": now + 60,
        "asset_id": "asset:winsrv2025-01",
        "profile_id": "t3-authorized-access-bounded",
        "operation_id": OPERATION_ID,
        "target": TARGET,
        "port": 22,
        "credential_ref": "credential:ssh-winsrv2025-01",
        "pinned_host_key": HOST_KEY,
        "command_ids": list(COMMAND_IDS),
        "command_registry_digest": REGISTRY_DIGEST,
        "approval_fingerprint": "a" * 64,
        "runtime_binding_fingerprint": "b" * 64,
        "limits": {"max_sessions": 1},
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
                "command_id": item,
                "attempted": True,
                "return_code": 0,
                "outcome": "succeeded",
                "sanitized_stdout": "synthetic",
                "duration_seconds": 0.01,
                "evidence_predicate_passed": True,
            }
            for item in COMMAND_IDS
        ]

    selected = T3AService(
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
    register_t3a_routes(app, service)
    return app.test_client()


@pytest.mark.parametrize(
    "mutation",
    [
        {"asset_id": "other"},
        {"port": 2222},
        {"profile_id": "other"},
        {"credential_ref": "credential:other"},
        {"operation_id": "other"},
        {"command_ids": ["unknown"]},
        {"command_ids": ["host_identity", "current_identity", "privilege_context"]},
        {"command_ids": [*COMMAND_IDS, "extra"]},
        {"pinned_host_key": ""},
        {"command_registry_digest": "c" * 64},
        {"approval_fingerprint": ""},
    ],
)
def test_invalid_binding_has_zero_resolver_and_runner_calls(service, mutation):
    response = client(service).post(
        "/api/v1/t3a/executions", json={"permit": encode(claims(**mutation))}
    )
    assert response.status_code == 401
    assert service.calls == {"resolve": 0, "run": 0}


def test_missing_bad_expired_and_target_denial_are_precredential(service):
    selected = client(service)
    assert selected.post("/api/v1/t3a/executions", json={}).status_code == 401
    assert (
        selected.post("/api/v1/t3a/executions", json={"permit": "bad"}).status_code
        == 401
    )
    expired = encode(claims(issued_at=1, expires_at=2))
    assert (
        selected.post("/api/v1/t3a/executions", json={"permit": expired}).status_code
        == 401
    )
    service.target_allowed = lambda target: False
    assert (
        selected.post(
            "/api/v1/t3a/executions", json={"permit": encode(claims())}
        ).status_code
        == 403
    )
    assert service.calls == {"resolve": 0, "run": 0}


def test_signature_tampering_and_replay(service):
    token = encode(claims())
    payload, signature = token.split(".")
    bad = payload + "." + signature[:-1] + ("A" if signature[-1] != "A" else "B")
    assert (
        client(service).post("/api/v1/t3a/executions", json={"permit": bad}).status_code
        == 401
    )
    selected = client(service)
    assert (
        selected.post("/api/v1/t3a/executions", json={"permit": token}).status_code
        == 200
    )
    assert (
        selected.post("/api/v1/t3a/executions", json={"permit": token}).status_code
        == 409
    )
    assert service.calls == {"resolve": 1, "run": 1}


def test_concurrent_nonce_consumption_admits_one(service):
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


def test_server_kill_switch_blocks_credential_resolution(service, tmp_path):
    kill = tmp_path / "KILL"
    kill.touch()
    service.kill_switch_path = kill
    response = client(service).post(
        "/api/v1/t3a/executions", json={"permit": encode(claims(nonce="kill-nonce"))}
    )
    assert response.status_code == 401
    assert service.calls == {"resolve": 0, "run": 0}
