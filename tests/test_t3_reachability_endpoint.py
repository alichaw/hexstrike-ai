import json
import sys
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hexstrike_t3_reachability import (  # noqa: E402
    ACTION_ID,
    T3SshReachabilityService,
    register_t3_reachability_routes,
)


def client(tmp_path, connector):
    config = tmp_path / "reachability.json"
    config.write_text(
        json.dumps(
            {
                "asset_id": "asset:winsrv2025-01",
                "target": "192.0.2.25",
                "port": 22,
            }
        )
    )
    app = Flask(__name__)
    register_t3_reachability_routes(
        app,
        T3SshReachabilityService(config, connector=connector),
    )
    return app.test_client()


def test_reachable_result_is_fixed_and_structured(tmp_path):
    selected = client(tmp_path, lambda target, port: "reachable")
    response = selected.post(
        "/api/v1/t3/ssh-reachability",
        json={"action_id": ACTION_ID, "asset_id": "asset:winsrv2025-01"},
    )
    assert response.status_code == 200
    assert response.get_json()["state"] == "reachable"
    assert response.get_json()["port"] == 22
    assert len(response.get_json()["target_binding"]) == 64


def test_caller_cannot_supply_target_port_or_command(tmp_path):
    selected = client(tmp_path, lambda target, port: "reachable")
    for field in ("target", "port", "command"):
        response = selected.post(
            "/api/v1/t3/ssh-reachability",
            json={
                "action_id": ACTION_ID,
                "asset_id": "asset:winsrv2025-01",
                field: "attacker-value",
            },
        )
        assert response.status_code == 403


def test_unknown_asset_denied_without_connect(tmp_path):
    calls = []
    selected = client(tmp_path, lambda target, port: calls.append((target, port)))
    response = selected.post(
        "/api/v1/t3/ssh-reachability",
        json={"action_id": ACTION_ID, "asset_id": "asset:unknown"},
    )
    assert response.status_code == 403
    assert calls == []


def test_connector_error_is_explicit(tmp_path):
    def failed(target, port):
        raise OSError("synthetic")

    selected = client(tmp_path, failed)
    response = selected.post(
        "/api/v1/t3/ssh-reachability",
        json={"action_id": ACTION_ID, "asset_id": "asset:winsrv2025-01"},
    )
    assert response.status_code == 200
    assert response.get_json()["state"] == "error"


@pytest.mark.parametrize(
    "update",
    [
        {"asset_id": "asset:other"},
        {"port": 2222},
        {"command": "whoami"},
    ],
)
def test_protected_config_schema_is_exact(tmp_path, update):
    config = tmp_path / "reachability.json"
    value = {
        "asset_id": "asset:winsrv2025-01",
        "target": "192.0.2.25",
        "port": 22,
    }
    value.update(update)
    config.write_text(json.dumps(value))
    service = T3SshReachabilityService(
        config, connector=lambda target, port: "reachable"
    )
    with pytest.raises(ValueError, match="configuration_invalid"):
        service._config()


def test_default_protected_config_requires_root_hexstrike_mode_0640(tmp_path):
    config = tmp_path / "reachability.json"
    config.write_text(
        json.dumps(
            {
                "asset_id": "asset:winsrv2025-01",
                "target": "192.0.2.25",
                "port": 22,
            }
        )
    )
    config.chmod(0o600)
    service = T3SshReachabilityService(
        config, connector=lambda target, port: "reachable"
    )
    service.require_protected_config = True
    with pytest.raises(ValueError, match="not_protected"):
        service._config()
