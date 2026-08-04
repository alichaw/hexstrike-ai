import hashlib
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hexstrike_t3c import (  # noqa: E402
    ACTION_ID,
    MARKER_CONTENT,
    MARKER_DIGEST,
    MARKER_PATH,
    SCENARIO_ID,
    T3CService,
    register_t3c_routes,
)
from hexstrike_t3_identity import IDENTITY_AGENT_PATH  # noqa: E402

NOW = 1_800_000_000


def authorization(tag="c1", issued=NOW, fill="a"):
    return f"{issued:08x}{tag}{fill * 30}"


class RecordingConnector:
    calls = []
    present = False
    content = b""
    fail = None

    def __init__(self, config):
        self.config = config

    def exists(self):
        self.calls.append("exists")
        if self.fail == "absence" and len(self.calls) == 1:
            raise RuntimeError("secret-target")
        if self.fail == "rollback" and self.calls.count("exists") > 1:
            return True
        return self.present

    def create(self):
        self.calls.append("create")
        if self.fail == "create":
            raise RuntimeError("secret-target")
        type(self).present = True
        type(self).content = MARKER_CONTENT.encode()

    def digest(self):
        self.calls.append("digest")
        if self.fail == "read":
            raise RuntimeError("secret-target")
        return (
            "0" * 64
            if self.fail == "digest"
            else hashlib.sha256(self.content).hexdigest()
        )

    def cleanup(self):
        self.calls.append("cleanup")
        if self.fail == "cleanup":
            raise RuntimeError("secret-target")
        type(self).present = False
        type(self).content = b""


@pytest.fixture(autouse=True)
def reset_connector(monkeypatch):
    RecordingConnector.calls = []
    RecordingConnector.present = False
    RecordingConnector.content = b""
    RecordingConnector.fail = None
    monkeypatch.setattr(
        socket, "socket", lambda *a, **k: pytest.fail("socket creation attempted")
    )
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: pytest.fail("DNS attempted")
    )


def config(tmp_path, **updates):
    value = {
        "assurance_profile": "poc",
        "scenario_id": SCENARIO_ID,
        "asset_id": "asset:winsrv2025-01",
        "target": "192.0.2.25",
        "credential_ref": "credential:fixture",
        "identity_agent": IDENTITY_AGENT_PATH,
        "username": "fixture-user",
        "pinned_host_key_file": "/fixture/known-hosts",
        "marker_path": MARKER_PATH,
        "marker_content_sha256": MARKER_DIGEST,
        "cleanup_required": True,
        "rollback_verification_required": True,
        "maximum_duration_seconds": 60,
        "maximum_tool_calls": 6,
        "isolated_lab_ready": True,
    }
    value.update(updates)
    path = tmp_path / "t3c.json"
    path.write_text(json.dumps(value))
    (tmp_path / "reachability.json").write_text(
        json.dumps(
            {
                "asset_id": "asset:winsrv2025-01",
                "target": value["target"],
                "port": 22,
            }
        )
    )
    return path


def client(tmp_path, **updates):
    service = T3CService(
        config(tmp_path, **updates),
        reachability_path=tmp_path / "reachability.json",
        connector_factory=RecordingConnector,
        clock=lambda: NOW,
    )
    app = Flask(__name__)
    register_t3c_routes(app, service)
    return app.test_client(), service


def body(auth=None):
    return {"authorization_id": auth or authorization(), "canonical_action": ACTION_ID}


def test_single_asset_fixed_lifecycle_and_single_use(tmp_path):
    selected, service = client(tmp_path)
    assert selected.post("/api/v1/t3c/executions", json=body()).status_code == 200
    result = selected.post("/api/v1/t3c/executions", json=body()).get_json()
    assert result["error"] == "authorization_replayed"
    assert RecordingConnector.calls == [
        "exists",
        "create",
        "exists",
        "digest",
        "cleanup",
        "exists",
    ]
    assert RecordingConnector.present is False
    assert service.credential_provider_invoked and service.connector_invoked


@pytest.mark.parametrize(
    "field",
    [
        "asset_id",
        "target",
        "port",
        "source",
        "destination",
        "path",
        "content",
        "command",
        "username",
        "credential",
        "ssh_key",
        "agent_socket",
        "limits",
        "assurance_profile",
        "cleanup",
        "rollback",
    ],
)
def test_illegal_scope_denied_before_resolution_consumption_or_connector(
    tmp_path, caplog, field
):
    selected, service = client(tmp_path)
    response = selected.post(
        "/api/v1/t3c/executions", json={**body(), field: "SENSITIVE-VALUE"}
    )
    assert response.status_code == 403
    assert response.get_json() == {
        "error": "poc_scope_denied",
        "connector_invoked": False,
    }
    assert (
        not service.target_resolved
        and not service.credential_provider_invoked
        and not service.connector_invoked
    )
    assert RecordingConnector.calls == []
    assert "event=poc_scope_denied connector_invoked=false" in caplog.text
    assert "SENSITIVE-VALUE" not in caplog.text


@pytest.mark.parametrize(
    "updates",
    [
        {"assurance_profile": "unknown"},
        {"asset_id": "asset:unapproved"},
        {"marker_path": r"C:\caller"},
        {"cleanup_required": False},
        {"maximum_tool_calls": 7},
        {"source_asset_id": "asset:second"},
    ],
)
def test_malformed_or_unapproved_configuration_fails_closed(tmp_path, updates):
    selected, service = client(tmp_path, **updates)
    assert selected.post("/api/v1/t3c/executions", json=body()).status_code == 403
    assert not service.credential_provider_invoked and RecordingConnector.calls == []


def test_missing_config_listener_starts_but_action_fails_closed(tmp_path):
    app = Flask(__name__)
    service = T3CService(
        tmp_path / "missing.json",
        reachability_path=tmp_path / "reachability.json",
        connector_factory=RecordingConnector,
        clock=lambda: NOW,
    )
    register_t3c_routes(app, service)
    assert (
        app.test_client().post("/api/v1/t3c/executions", json=body()).status_code == 403
    )
    assert RecordingConnector.calls == []


def test_nonregistered_target_is_rejected_before_connector(tmp_path):
    selected, service = client(tmp_path)
    reachability = tmp_path / "reachability.json"
    value = json.loads(reachability.read_text())
    value["target"] = "198.51.100.8"
    reachability.write_text(json.dumps(value))
    response = selected.post("/api/v1/t3c/executions", json=body())
    assert response.status_code == 403
    assert not service.connector_invoked
    assert RecordingConnector.calls == []


@pytest.mark.parametrize(
    "failure,expected,calls",
    [
        ("absence", "create_failed", ["exists"]),
        ("create", "create_failed", ["exists", "create"]),
        (
            "read",
            "proof_failed",
            ["exists", "create", "exists", "digest", "cleanup", "exists"],
        ),
        (
            "digest",
            "proof_failed",
            ["exists", "create", "exists", "digest", "cleanup", "exists"],
        ),
        (
            "cleanup",
            "cleanup_failed",
            ["exists", "create", "exists", "digest", "cleanup"],
        ),
        (
            "rollback",
            "rollback_failed",
            ["exists", "create", "exists", "digest", "cleanup", "exists"],
        ),
    ],
)
def test_failure_injection_is_sanitized_and_cleanup_is_mandatory(
    tmp_path, failure, expected, calls
):
    RecordingConnector.fail = failure
    selected, _ = client(tmp_path)
    response = selected.post("/api/v1/t3c/executions", json=body())
    assert response.status_code == 422
    value = response.get_json()
    assert value["status"] == expected
    assert RecordingConnector.calls == calls
    assert "secret-target" not in response.text
    if failure in {"read", "digest"}:
        assert "cleanup" in calls
    if failure in {"cleanup", "rollback"}:
        assert value["operator_warning"]


def test_marker_preexisting_is_not_deleted(tmp_path):
    RecordingConnector.present = True
    selected, _ = client(tmp_path)
    value = selected.post("/api/v1/t3c/executions", json=body()).get_json()
    assert value["status"] == "marker_preexisting"
    assert RecordingConnector.calls == ["exists"] and RecordingConnector.present


def test_expiry_future_cross_stage_action_and_concurrent_reuse(tmp_path):
    selected, _ = client(tmp_path)
    for auth in (
        authorization(issued=NOW - 60),
        authorization(issued=NOW + 6),
        authorization(tag="b1"),
    ):
        assert (
            selected.post("/api/v1/t3c/executions", json=body(auth)).status_code == 403
        )
    assert (
        selected.post(
            "/api/v1/t3c/executions", json={**body(), "canonical_action": "wrong"}
        ).status_code
        == 403
    )
    auth = authorization(fill="f")
    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = list(
            pool.map(
                lambda _: (
                    selected.post("/api/v1/t3c/executions", json=body(auth)).status_code
                ),
                range(2),
            )
        )
    assert sorted(codes) == [200, 409]
