import json
import sys
from pathlib import Path

from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hexstrike_t3c import ACTION_ID, T3CService, register_t3c_routes  # noqa: E402

NOW = 1_800_000_000


def authorization(fill="a"):
    return f"{NOW:08x}c1{fill * 30}"


def client(tmp_path, marker="T3C_SYNTHETIC_PROOF_7F91"):
    config = tmp_path / "t3c.json"
    config.write_text(
        json.dumps(
            {
                "assurance_profile": "poc",
                "scenario_id": "lab.synthetic-marker.v1",
                "source_asset_id": "asset:source",
                "destination_asset_id": "asset:destination",
                "destination_target": "10.77.0.11",
                "credential_ref": "credential:t3c",
                "identity_agent": "/run/agent.sock",
                "username": "lab-user",
                "pinned_host_key_file": "/etc/hexstrike/t3c-known-hosts",
                "proof_marker": marker,
                "rollback_checkpoint": "snapshot:clean",
                "isolated_lab": True,
                "rollback_ready": True,
            }
        )
    )
    app = Flask(__name__)
    register_t3c_routes(
        app, T3CService(config, runner=lambda _: marker, clock=lambda: NOW)
    )
    return app.test_client()


def test_fixed_t3c_endpoint_returns_marker(tmp_path):
    response = client(tmp_path).post(
        "/api/v1/t3c/executions",
        json={
            "authorization_id": authorization(),
            "canonical_action": ACTION_ID,
        },
    )
    assert response.status_code == 200
    assert response.get_json()["proof_output"] == "T3C_SYNTHETIC_PROOF_7F91"


def test_t3c_authorization_is_single_use(tmp_path):
    selected = client(tmp_path)
    body = {
        "authorization_id": authorization(),
        "canonical_action": ACTION_ID,
    }
    assert selected.post("/api/v1/t3c/executions", json=body).status_code == 200
    assert selected.post("/api/v1/t3c/executions", json=body).status_code == 409


def test_endpoint_rejects_caller_execution_fields_and_unknown_action(tmp_path):
    selected = client(tmp_path)
    for body in (
        {"authorization_id": authorization(), "canonical_action": "unknown"},
        {
            "authorization_id": authorization(),
            "canonical_action": ACTION_ID,
            "command": "id",
        },
        {
            "authorization_id": authorization(),
            "canonical_action": ACTION_ID,
            "target": "8.8.8.8",
        },
    ):
        assert selected.post("/api/v1/t3c/executions", json=body).status_code == 403
