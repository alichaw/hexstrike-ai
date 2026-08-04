import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hexstrike_t3_poc import T3PocService, register_t3_poc_routes  # noqa: E402
from hexstrike_t3_reachability import target_binding  # noqa: E402
from hexstrike_t3a import COMMAND_IDS, OPERATION_ID as T3A_ACTION  # noqa: E402
from hexstrike_t3b import (  # noqa: E402
    DEFINITION_DIGESTS,
    OPERATION_ID as T3B_ACTION,
    SCRIPTS,
)

TARGET = "192.0.2.25"
NOW = 1_800_000_000


def authorization(stage_tag, fill):
    return f"{NOW:08x}{stage_tag}{fill * 30}"


def service(tmp_path, calls):
    reachability = tmp_path / "reachability.json"
    runtime = tmp_path / "runtime.json"
    matrix = tmp_path / "matrix.json"
    credentials = tmp_path / "credentials.json"
    reachability.write_text(
        json.dumps(
            {
                "asset_id": "asset:winsrv2025-01",
                "target": TARGET,
                "port": 22,
            }
        )
    )
    runtime.write_text(
        json.dumps(
            {
                "assurance_profile": "poc",
                "asset_id": "asset:winsrv2025-01",
                "target_binding": target_binding("asset:winsrv2025-01", TARGET, 22),
                "pinned_host_key": "ssh-ed25519 " + "A" * 43,
            }
        )
    )
    matrix.write_text(json.dumps({"allowed_targets": [f"{TARGET}/32"]}))
    credentials.write_text(json.dumps({"credentials": {}}))

    def t3a_runner(claims, credential):
        calls.append("t3a")
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

    def t3b_runner(claims, credential):
        calls.append("t3b")
        now = datetime.now(timezone.utc).isoformat()
        return [
            {
                "action_id": action,
                "definition_digest": DEFINITION_DIGESTS[action],
                "started_at": now,
                "completed_at": now,
                "duration_seconds": 0.01,
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
            for action in SCRIPTS
        ]

    selected = T3PocService(
        reachability_path=reachability,
        runtime_path=runtime,
        target_matrix_path=matrix,
        credential_config_path=credentials,
        authorization_db_path=tmp_path / "authorizations.sqlite3",
        kill_switch_path=tmp_path / "KILL",
        t3a_runner=t3a_runner,
        t3b_runner=t3b_runner,
        protected=False,
        clock=lambda: NOW,
    )

    def resolver(ref, asset):
        return {
            "username": "poc_websvc",
            "identity_agent": "/run/fake.sock",
        }

    selected.t3a.resolve_credential = resolver
    selected.t3b.resolve_credential = resolver
    return selected


def client(tmp_path, calls):
    app = Flask(__name__)
    register_t3_poc_routes(app, service(tmp_path, calls))
    return app.test_client()


def test_illegal_scope_is_403_without_connector(tmp_path, caplog):
    calls = []
    selected = client(tmp_path, calls)
    base = {
        "authorization_id": authorization("a1", "a"),
        "canonical_action": T3A_ACTION,
    }
    bodies = [
        {"authorization_id": authorization("a1", "a"), "canonical_action": "unknown"}
    ]
    for field in (
        "target",
        "port",
        "command",
        "username",
        "credential_ref",
        "password",
        "private_key",
        "host_key",
        "limits",
        "assurance_profile",
        "asset_id",
    ):
        bodies.append({**base, field: "caller-value"})
    for body in bodies:
        assert selected.post("/api/v1/t3a/poc-executions", json=body).status_code == 403
    assert calls == []
    assert "event=poc_scope_denied connector_invoked=false" in caplog.text


def test_t3a_and_t3b_poc_actions_are_fixed_and_single_use(tmp_path):
    calls = []
    selected = client(tmp_path, calls)
    t3a_body = {
        "authorization_id": authorization("a1", "a"),
        "canonical_action": T3A_ACTION,
    }
    t3b_body = {
        "authorization_id": authorization("b1", "b"),
        "canonical_action": T3B_ACTION,
    }
    assert selected.post("/api/v1/t3a/poc-executions", json=t3a_body).status_code == 200
    assert selected.post("/api/v1/t3a/poc-executions", json=t3a_body).status_code == 409
    assert selected.post("/api/v1/t3b/poc-executions", json=t3b_body).status_code == 200
    assert selected.post("/api/v1/t3b/poc-executions", json=t3b_body).status_code == 409
    assert calls == ["t3a", "t3b"]


def test_expired_and_wrong_stage_authorizations_are_rejected_before_connector(
    tmp_path,
):
    calls = []
    selected = client(tmp_path, calls)
    expired = authorization("a1", "e")
    expired = f"{NOW - 60:08x}{expired[8:]}"
    assert (
        selected.post(
            "/api/v1/t3a/poc-executions",
            json={"authorization_id": expired, "canonical_action": T3A_ACTION},
        ).status_code
        == 403
    )
    assert (
        selected.post(
            "/api/v1/t3b/poc-executions",
            json={
                "authorization_id": authorization("a1", "a"),
                "canonical_action": T3B_ACTION,
            },
        ).status_code
        == 403
    )
    assert calls == []


def test_poc_routes_are_absent_without_explicit_profile(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_ASSURANCE_PROFILE", raising=False)
    app = Flask(__name__)
    register_t3_poc_routes(app)
    assert (
        app.test_client()
        .post(
            "/api/v1/t3a/poc-executions",
            json={
                "authorization_id": authorization("a1", "a"),
                "canonical_action": T3A_ACTION,
            },
        )
        .status_code
        == 404
    )


def test_poc_route_registration_does_not_eagerly_load_action_configuration(
    monkeypatch,
):
    monkeypatch.setattr(
        "hexstrike_t3_poc.T3PocService",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("eager load")),
    )
    app = Flask(__name__)
    register_t3_poc_routes(app, assurance_profile="poc")
    assert any(
        rule.rule == "/api/v1/t3a/poc-executions" for rule in app.url_map.iter_rules()
    )
