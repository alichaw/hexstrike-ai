import json
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hexstrike_t3_execution import (  # noqa: E402
    ACTIONS,
    ASSET_ID,
    FIXED_WINDOWS_COMMANDS,
    IDENTITY_ACTION,
    REACHABILITY_ACTION,
    FakeWindowsSshAdapter,
    UnifiedT3Service,
    authorization_digest,
    canonical_digest,
    load_runtime,
    register_unified_t3_route,
)


def runtime(tmp_path):
    return {
        "schema_version": "hexstrike-t3-runtime/v1",
        "runtime_revision": "12345678-1234-5678-1234-567812345678",
        "assets": {
            ASSET_ID: {
                "target": "192.0.2.25",
                "port": 22,
                "credential_ref": "credential:synthetic",
                "username": "synthetic-user",
                "identity_agent": str(tmp_path / "agent.sock"),
                "pinned_host_key": "ssh-ed25519 " + "A" * 43,
            }
        },
        "approval_database": str(tmp_path / "approvals.sqlite3"),
        "evidence_root": str(tmp_path / "evidence"),
        "kill_switch_file": str(tmp_path / "KILL"),
        "action_policy": {"enabled_action_ids": list(ACTIONS)},
    }


def database(value):
    with sqlite3.connect(value["approval_database"]) as db:
        db.execute(
            "CREATE TABLE approvals (authorization_id_digest TEXT PRIMARY KEY, action_id TEXT, "
            "asset_id TEXT, runtime_revision TEXT, runtime_digest TEXT, state TEXT, issued_at INTEGER, "
            "expires_at INTEGER, consumed_at INTEGER, invalidated_at INTEGER, approving_uid INTEGER, "
            "approval_note_digest TEXT)"
        )
    Path(value["approval_database"]).chmod(0o600)


def approve(
    value, authorization, action, *, now=100, asset=ASSET_ID, revision=None, digest=None
):
    with sqlite3.connect(value["approval_database"]) as db:
        db.execute(
            "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, NULL, NULL, 1, ?)",
            (
                authorization_digest(authorization),
                action,
                asset,
                revision or value["runtime_revision"],
                digest or canonical_digest(value),
                now - 1,
                now + 100,
                canonical_digest("note"),
            ),
        )


class FakeProcess:
    def __init__(self, outputs=None):
        self.calls = []
        self.outputs = iter(
            outputs
            or ["DOMAIN\\reader\n", "WINHOST\n", "Microsoft Windows [Version 10.0]\n"]
        )

    def __call__(self, argv, timeout):
        self.calls.append((argv, timeout))
        return subprocess.CompletedProcess(argv, 0, next(self.outputs), "")


def service(value, *, process=None, connector=None):
    adapter = FakeWindowsSshAdapter(
        process=process or FakeProcess(), connector=connector or (lambda *_: None)
    )
    return UnifiedT3Service(value, adapter=adapter, clock=lambda: 100)


def seed_reachability(value):
    evidence_root = Path(value["evidence_root"])
    evidence_root.mkdir(mode=0o700)
    evidence_root.chmod(0o700)
    root = evidence_root / "seed"
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    doc = {
        "schema_version": "hexstrike-t3-evidence/v1",
        "authorization_id_digest": "0" * 64,
        "action_id": REACHABILITY_ACTION,
        "asset_id": ASSET_ID,
        "runtime_digest": canonical_digest(value),
        "status": "completed",
        "tool_calls": 1,
        "evidence": {"reachability": "reachable"},
    }
    doc["seal"] = canonical_digest(doc)
    (root / f"{canonical_digest(REACHABILITY_ACTION)}.json").write_text(json.dumps(doc))


def test_registry_is_exact_minimal_slice():
    assert list(ACTIONS) == [REACHABILITY_ACTION, IDENTITY_ACTION]
    assert [item for _, command in FIXED_WINDOWS_COMMANDS for item in command] == [
        "whoami",
        "hostname",
        "cmd.exe",
        "/d",
        "/c",
        "ver",
    ]


def test_exact_route_contract_replay_and_sealed_evidence(tmp_path):
    value = runtime(tmp_path)
    database(value)
    auth = "synthetic_authorization_0001"
    approve(value, auth, REACHABILITY_ACTION)
    app = Flask(__name__)
    register_unified_t3_route(app, service(value))
    client = app.test_client()
    assert (
        client.post(
            "/api/v1/t3/executions",
            json={
                "authorization_id": auth,
                "canonical_action": REACHABILITY_ACTION,
                "target": "bad",
            },
        ).status_code
        == 400
    )
    result = client.post(
        "/api/v1/t3/executions",
        json={"authorization_id": auth, "canonical_action": REACHABILITY_ACTION},
    )
    assert result.status_code == 200
    body = result.get_json()
    assert auth not in json.dumps(body)
    assert set(body) == {
        "schema_version",
        "authorization_id_digest",
        "action_id",
        "status",
        "runtime_digest",
        "executor_family",
        "tool_calls",
        "evidence_ref",
        "evidence_digest",
    }
    evidence = json.loads(
        (Path(value["evidence_root"]) / body["evidence_ref"]).read_text()
    )
    seal = evidence.pop("seal")
    assert seal == canonical_digest(evidence)
    assert set(evidence) == {
        "schema_version",
        "authorization_id_digest",
        "action_id",
        "asset_id",
        "runtime_digest",
        "status",
        "tool_calls",
        "evidence",
    }
    assert (
        client.post(
            "/api/v1/t3/executions",
            json={"authorization_id": auth, "canonical_action": REACHABILITY_ACTION},
        ).status_code
        == 409
    )
    audits = list((Path(value["evidence_root"]) / "audit").glob("*.json"))
    assert json.loads(audits[-1].read_text())["policy_decision"] == "replay_denied"


@pytest.mark.parametrize(
    "body",
    [
        {},
        {
            "authorization_id": "synthetic_authorization_0002",
            "canonical_action": "reachability",
        },
        {
            "authorization_id": "synthetic_authorization_0002",
            "canonical_action": "t3.unknown.v1",
        },
    ],
)
def test_missing_alias_unknown_fail_closed(tmp_path, body):
    value = runtime(tmp_path)
    database(value)
    app = Flask(__name__)
    register_unified_t3_route(app, service(value))
    assert app.test_client().post("/api/v1/t3/executions", json=body).status_code in {
        400,
        403,
    }


@pytest.mark.parametrize("change", ["asset", "revision", "digest", "expired", "action"])
def test_approval_bindings_fail_without_transport(tmp_path, change):
    value = runtime(tmp_path)
    database(value)
    calls = []
    auth = "synthetic_authorization_0003"
    kwargs = (
        {"asset": "asset:wrong"}
        if change == "asset"
        else {"revision": "22345678-1234-5678-1234-567812345678"}
        if change == "revision"
        else {"digest": "0" * 64}
        if change == "digest"
        else {"now": -200}
        if change == "expired"
        else {}
    )
    approve(
        value,
        auth,
        IDENTITY_ACTION if change == "action" else REACHABILITY_ACTION,
        **kwargs,
    )
    with pytest.raises(ValueError, match="authorization_rejected"):
        service(value, connector=lambda *_: calls.append(True)).execute(
            auth, REACHABILITY_ACTION
        )
    assert calls == []


def test_kill_switch_denial_does_not_consume_and_writes_audit(tmp_path):
    value = runtime(tmp_path)
    database(value)
    auth = "synthetic_authorization_0004"
    approve(value, auth, REACHABILITY_ACTION)
    Path(value["kill_switch_file"]).touch()
    with pytest.raises(ValueError, match="kill_switch_engaged"):
        service(value).execute(auth, REACHABILITY_ACTION)
    with sqlite3.connect(value["approval_database"]) as db:
        assert db.execute("SELECT state FROM approvals").fetchone()[0] == "pending"
    audit = json.loads(
        next((Path(value["evidence_root"]) / "audit").glob("*.json")).read_text()
    )
    assert audit["policy_decision"] == "kill_switch_denied" and auth not in json.dumps(
        audit
    )


def test_identity_uses_only_runtime_and_fixed_commands(tmp_path):
    value = runtime(tmp_path)
    database(value)
    seed_reachability(value)
    auth = "synthetic_authorization_0005"
    approve(value, auth, IDENTITY_ACTION)
    process = FakeProcess()
    result = service(value, process=process).execute(auth, IDENTITY_ACTION)
    assert result["status"] == "completed" and len(process.calls) == 3
    for (argv, timeout), (_, command) in zip(
        process.calls, FIXED_WINDOWS_COMMANDS, strict=True
    ):
        assert argv[-len(command) :] == list(command)
        assert value["assets"][ASSET_ID]["target"] in argv
        assert timeout == 15


def test_host_key_output_timeout_and_exception_fail_sanitized(tmp_path):
    value = runtime(tmp_path)
    database(value)
    seed_reachability(value)
    for index, process in enumerate(
        (
            lambda argv, timeout: subprocess.CompletedProcess(
                argv, 255, "", "host key mismatch SYNTHETIC_SECRET"
            ),
            lambda argv, timeout: subprocess.CompletedProcess(argv, 0, "X" * 5000, ""),
            lambda *_: (_ for _ in ()).throw(RuntimeError("SYNTHETIC_SECRET")),
        )
    ):
        auth = f"synthetic_authorization_failure_{index:02d}"
        approve(value, auth, IDENTITY_ACTION)
        result = service(value, process=process).execute(auth, IDENTITY_ACTION)
        evidence = (Path(value["evidence_root"]) / result["evidence_ref"]).read_text()
        assert result["status"] == "failed" and "SYNTHETIC_SECRET" not in evidence


def test_runtime_file_metadata_and_schema(tmp_path):
    value = runtime(tmp_path)
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    assert load_runtime(path) == value
    path.chmod(0o644)
    with pytest.raises(ValueError, match="runtime_invalid"):
        load_runtime(path)


def test_fake_transport_proof_no_real_adapter(tmp_path, monkeypatch):
    value = runtime(tmp_path)
    database(value)
    auth = "synthetic_authorization_0006"
    approve(value, auth, REACHABILITY_ACTION)
    monkeypatch.setattr(
        "socket.create_connection", lambda *_args, **_kwargs: pytest.fail("socket used")
    )
    monkeypatch.setattr(
        "subprocess.run", lambda *_args, **_kwargs: pytest.fail("process used")
    )
    assert service(value).execute(auth, REACHABILITY_ACTION)["status"] == "completed"


def test_concurrent_single_use_is_atomic_and_failure_stays_consumed(tmp_path):
    value = runtime(tmp_path)
    database(value)
    auth = "synthetic_authorization_concurrent"
    approve(value, auth, REACHABILITY_ACTION)
    selected = service(value)

    def execute_once():
        try:
            return selected.execute(auth, REACHABILITY_ACTION)["status"]
        except ValueError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _index: execute_once(), range(2)))
    assert sorted(outcomes) == ["authorization_rejected", "completed"]

    failed_auth = "synthetic_authorization_failure_consumed"
    approve(value, failed_auth, REACHABILITY_ACTION)
    failed = service(
        value,
        connector=lambda *_: (_ for _ in ()).throw(RuntimeError("synthetic")),
    ).execute(failed_auth, REACHABILITY_ACTION)
    assert failed["status"] == "failed"
    with sqlite3.connect(value["approval_database"]) as db:
        state = db.execute(
            "SELECT state FROM approvals WHERE authorization_id_digest=?",
            (authorization_digest(failed_auth),),
        ).fetchone()
    assert state == ("consumed",)
