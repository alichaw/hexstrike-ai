import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hexstrike_t3_poc import CREDENTIAL_REF, T3PocService, _protected_json  # noqa: E402
from hexstrike_t3_identity import IDENTITY_AGENT_PATH  # noqa: E402
from hexstrike_t3_profile import resolve_assurance_profile  # noqa: E402
from hexstrike_t3_reachability import ASSET_ID, target_binding  # noqa: E402
from hexstrike_t3c import MARKER_DIGEST, MARKER_PATH, T3CService  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGET = "192.0.2.25"


class ProtectedPath:
    def __init__(self, path, *, uid=0, gid=123, mode=0o640):
        self.path = Path(path)
        self.uid = uid
        self.gid = gid
        self.mode = mode

    def stat(self):
        return SimpleNamespace(
            st_uid=self.uid,
            st_gid=self.gid,
            st_mode=stat.S_IFREG | self.mode,
        )

    def read_text(self, **kwargs):
        return self.path.read_text(**kwargs)


def _write(path, value):
    path.write_text(json.dumps(value))
    return path


def _common_files(tmp_path, runtime_updates=None, matrix_updates=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    reachability = _write(
        tmp_path / "reachability.json",
        {"asset_id": ASSET_ID, "target": TARGET, "port": 22},
    )
    runtime = json.loads((ROOT / "t3-poc-runtime.example.json").read_text())
    runtime.update(
        {
            "target_binding": target_binding(ASSET_ID, TARGET, 22),
            "pinned_host_key": "ssh-ed25519 " + "A" * 43,
        }
    )
    runtime.update(runtime_updates or {})
    runtime_path = _write(tmp_path / "runtime.json", runtime)
    matrix = {"allowed_targets": [f"{TARGET}/32"]}
    matrix.update(matrix_updates or {})
    matrix_path = _write(tmp_path / "matrix.json", matrix)
    credentials = json.loads((ROOT / "t3a-credentials.example.json").read_text())
    mapping = credentials["credentials"][CREDENTIAL_REF]
    mapping["username"] = "fixture-user"
    mapping["identity_agent"] = IDENTITY_AGENT_PATH
    credentials_path = _write(tmp_path / "credentials.json", credentials)
    return reachability, runtime_path, matrix_path, credentials_path


def test_examples_are_accepted_after_placeholder_substitution(tmp_path):
    reachability, runtime, matrix, credentials = _common_files(tmp_path)
    service = T3PocService(
        reachability_path=reachability,
        runtime_path=runtime,
        target_matrix_path=matrix,
        credential_config_path=ProtectedPath(credentials),
        authorization_db_path=tmp_path / "spent.sqlite3",
        protected=False,
        t3a_runner=lambda *_: [],
        t3b_runner=lambda *_: [],
    )
    assert service.t3a.resolve_credential(CREDENTIAL_REF, ASSET_ID) == {
        "username": "fixture-user",
        "identity_agent": IDENTITY_AGENT_PATH,
    }

    t3c = json.loads((ROOT / "t3c-runtime.example.json").read_text())
    t3c.update(
        {
            "target": TARGET,
            "credential_ref": CREDENTIAL_REF,
            "identity_agent": IDENTITY_AGENT_PATH,
            "username": "fixture-user",
            "pinned_host_key_file": "/fixture/known-hosts",
        }
    )
    t3c_path = _write(tmp_path / "t3c.json", t3c)
    loaded = T3CService(
        t3c_path,
        reachability_path=reachability,
        connector_factory=lambda _: None,
    )._config()
    assert loaded["marker_path"] == MARKER_PATH
    assert loaded["marker_content_sha256"] == MARKER_DIGEST


@pytest.mark.parametrize(
    "updates",
    [
        {"assurance_profile": None},
        {"extra": "rejected"},
        {"asset_id": "asset:other"},
        {"target_binding": "0" * 64},
    ],
)
def test_common_runtime_missing_extra_or_inconsistent_values_fail_closed(
    tmp_path, updates
):
    if updates.get("assurance_profile") is None:
        updates = {"remove": "assurance_profile"}
    reachability, runtime, matrix, credentials = _common_files(tmp_path)
    value = json.loads(runtime.read_text())
    removed = updates.pop("remove", None)
    if removed:
        value.pop(removed)
    value.update(updates)
    runtime.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="poc_runtime_configuration_invalid"):
        T3PocService(
            reachability_path=reachability,
            runtime_path=runtime,
            target_matrix_path=matrix,
            credential_config_path=credentials,
            protected=False,
        )


def test_inconsistent_target_matrix_and_credential_asset_fail_closed(tmp_path):
    reachability, runtime, matrix, credentials = _common_files(
        tmp_path, matrix_updates={"allowed_targets": ["198.51.100.20/32"]}
    )
    with pytest.raises(ValueError, match="poc_target_matrix_invalid"):
        T3PocService(
            reachability_path=reachability,
            runtime_path=runtime,
            target_matrix_path=matrix,
            credential_config_path=credentials,
            protected=False,
        )

    _, _, matrix, credentials = _common_files(tmp_path / "credential")
    value = json.loads(credentials.read_text())
    value["credentials"][CREDENTIAL_REF]["asset_id"] = "asset:other"
    credentials.write_text(json.dumps(value))
    service = T3PocService(
        reachability_path=tmp_path / "credential/reachability.json",
        runtime_path=tmp_path / "credential/runtime.json",
        target_matrix_path=matrix,
        credential_config_path=ProtectedPath(credentials),
        protected=False,
    )
    with pytest.raises(ValueError, match="credential_binding_invalid"):
        service.t3a.resolve_credential(CREDENTIAL_REF, ASSET_ID)


@pytest.mark.parametrize("missing", ["asset_id", "username", "identity_agent"])
def test_missing_credential_mapping_keys_fail_closed(tmp_path, missing):
    reachability, runtime, matrix, credentials = _common_files(tmp_path)
    value = json.loads(credentials.read_text())
    value["credentials"][CREDENTIAL_REF].pop(missing)
    credentials.write_text(json.dumps(value))
    service = T3PocService(
        reachability_path=reachability,
        runtime_path=runtime,
        target_matrix_path=matrix,
        credential_config_path=ProtectedPath(credentials),
        protected=False,
    )
    with pytest.raises(ValueError, match="credential_"):
        service.t3a.resolve_credential(CREDENTIAL_REF, ASSET_ID)


@pytest.mark.parametrize(
    "uid,mode,group",
    [
        (1000, 0o640, "hexstrike"),
        (0, 0o600, "hexstrike"),
        (0, 0o646, "hexstrike"),
        (0, 0o640, "other"),
    ],
)
def test_protected_loader_rejects_incorrect_owner_mode_or_group(
    tmp_path, monkeypatch, uid, mode, group
):
    path = _write(tmp_path / "config.json", {})
    original_fstat = __import__("os").fstat
    monkeypatch.setattr(
        "hexstrike_t3_config.grp.getgrgid", lambda _: SimpleNamespace(gr_name=group)
    )
    monkeypatch.setattr(
        "hexstrike_t3_config.os.fstat",
        lambda fd: SimpleNamespace(
            st_uid=uid,
            st_gid=original_fstat(fd).st_gid,
            st_mode=stat.S_IFREG | mode,
        ),
    )
    with pytest.raises(ValueError, match="protected_configuration_unsafe_metadata"):
        _protected_json(path)


def test_protected_loader_accepts_root_hexstrike_mode_0640(tmp_path, monkeypatch):
    path = _write(tmp_path / "config.json", {"safe": True})
    original_fstat = __import__("os").fstat
    monkeypatch.setattr(
        "hexstrike_t3_config.grp.getgrgid",
        lambda _: SimpleNamespace(gr_name="hexstrike"),
    )
    monkeypatch.setattr(
        "hexstrike_t3_config.os.fstat",
        lambda fd: SimpleNamespace(
            st_uid=0,
            st_gid=original_fstat(fd).st_gid,
            st_mode=stat.S_IFREG | 0o640,
        ),
    )
    assert _protected_json(path) == {"safe": True}


def test_protected_loader_reports_missing_and_unreadable_files(tmp_path, monkeypatch):
    missing = tmp_path / "missing.json"
    with pytest.raises(
        ValueError, match="protected_configuration_missing:missing.json"
    ):
        _protected_json(missing)
    path = _write(tmp_path / "protected.json", {})
    monkeypatch.setattr(
        "hexstrike_t3_config.os.open",
        lambda *a, **k: (_ for _ in ()).throw(PermissionError()),
    )
    with pytest.raises(
        ValueError, match="protected_configuration_unreadable:protected.json"
    ):
        _protected_json(path)


@pytest.mark.parametrize(
    "updates,error",
    [
        ({"maximum_tool_calls": 7}, "scenario_limits_invalid"),
        ({"extra": "rejected"}, "scenario_configuration_invalid"),
    ],
)
def test_t3c_inconsistent_limits_and_unknown_keys_fail_closed(tmp_path, updates, error):
    value = json.loads((ROOT / "t3c-runtime.example.json").read_text())
    value.update(
        {
            "target": TARGET,
            "credential_ref": CREDENTIAL_REF,
            "identity_agent": IDENTITY_AGENT_PATH,
            "username": "fixture-user",
            "pinned_host_key_file": "/fixture/known-hosts",
        }
    )
    value.update(updates)
    path = _write(tmp_path / "t3c.json", value)
    with pytest.raises(ValueError, match=error):
        T3CService(path, reachability_path=_common_files(tmp_path / "reach")[0])._config()


def test_assurance_profile_never_falls_back():
    for environment in ({}, {"HEXSTRIKE_ASSURANCE_PROFILE": "unknown"}):
        with pytest.raises(RuntimeError, match="explicitly poc or hardened"):
            resolve_assurance_profile(environment)


@pytest.mark.parametrize(
    "identity_agent",
    ["/run/user/1000/transient-agent.sock", "/tmp/agent.sock", "/protected/key"],
)
def test_credential_loader_rejects_non_contract_identity_agents(
    tmp_path, identity_agent
):
    reachability, runtime, matrix, credentials = _common_files(tmp_path)
    value = json.loads(credentials.read_text())
    value["credentials"][CREDENTIAL_REF]["identity_agent"] = identity_agent
    credentials.write_text(json.dumps(value))
    service = T3PocService(
        reachability_path=reachability,
        runtime_path=runtime,
        target_matrix_path=matrix,
        credential_config_path=ProtectedPath(credentials),
        protected=False,
    )
    with pytest.raises(ValueError, match="credential_configuration_invalid"):
        service.t3a.resolve_credential(CREDENTIAL_REF, ASSET_ID)


def test_t3c_loader_requires_repository_identity_agent_contract(tmp_path):
    value = json.loads((ROOT / "t3c-runtime.example.json").read_text())
    value.update(
        {
            "target": TARGET,
            "credential_ref": CREDENTIAL_REF,
            "identity_agent": "/run/user/1000/transient-agent.sock",
            "username": "fixture-user",
            "pinned_host_key_file": "/fixture/known-hosts",
        }
    )
    path = _write(tmp_path / "t3c.json", value)
    with pytest.raises(ValueError, match="scenario_identity_agent_invalid"):
        T3CService(path, reachability_path=_common_files(tmp_path / "reach")[0])._config()
