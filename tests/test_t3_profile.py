import sys
import importlib
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hexstrike_t3_poc import register_t3_poc_routes  # noqa: E402
from hexstrike_t3_execution import register_production_unified_t3_route  # noqa: E402
from hexstrike_t3_profile import (  # noqa: E402
    assurance_audit_record,
    resolve_assurance_profile,
)
from hexstrike_t3a import register_t3a_routes  # noqa: E402


@pytest.mark.parametrize("value", ["poc", "hardened"])
def test_only_exact_profiles_are_accepted(value):
    assert resolve_assurance_profile({"HEXSTRIKE_ASSURANCE_PROFILE": value}) == value


@pytest.mark.parametrize(
    "environment", [{}, {"HEXSTRIKE_ASSURANCE_PROFILE": "unknown"}]
)
def test_missing_or_unknown_profile_fails_closed(environment):
    with pytest.raises(RuntimeError, match="explicitly poc or hardened"):
        resolve_assurance_profile(environment)


def test_hardened_missing_permit_does_not_enable_poc(monkeypatch):
    monkeypatch.delenv("HEXSTRIKE_EXECUTION_PERMIT_SECRET", raising=False)
    app = Flask(__name__)
    register_t3a_routes(app, assurance_profile="hardened")
    register_t3_poc_routes(app, assurance_profile="hardened")
    paths = {rule.rule for rule in app.url_map.iter_rules()}
    assert "/api/v1/t3a/executions" not in paths
    assert "/api/v1/t3a/poc-executions" not in paths


def test_explicit_poc_enables_poc_routes(monkeypatch):
    class Stub:
        def __init__(self, **kwargs):
            pass

    monkeypatch.setattr("hexstrike_t3_poc.T3PocService", Stub)
    app = Flask(__name__)
    register_t3_poc_routes(app, assurance_profile="poc")
    paths = {rule.rule for rule in app.url_map.iter_rules()}
    assert "/api/v1/t3a/poc-executions" in paths
    assert "/api/v1/t3b/poc-executions" in paths


def test_production_unified_route_is_registered_once_and_lazy():
    app = Flask(__name__)
    register_production_unified_t3_route(app, assurance_profile="poc")
    register_production_unified_t3_route(app, assurance_profile="poc")
    paths = [rule.rule for rule in app.url_map.iter_rules()]
    assert paths.count("/api/v1/t3/executions") == 1
    assert app.test_client().post("/api/v1/t3/executions", json={}).status_code == 400


def test_minimal_production_app_factory_registers_only_unified_route(monkeypatch):
    monkeypatch.setenv("HEXSTRIKE_ASSURANCE_PROFILE", "poc")
    sys.modules.pop("hexstrike_t3_app", None)
    module = importlib.import_module("hexstrike_t3_app")
    paths = {rule.rule for rule in module.create_app().url_map.iter_rules()}
    assert paths == {"/static/<path:filename>", "/api/v1/t3/executions"}


def test_production_app_startup_contains_one_unified_registration():
    source = (Path(__file__).resolve().parents[1] / "hexstrike_t3_app.py").read_text(
        encoding="utf-8"
    )
    invocation = "register_production_unified_t3_route("
    assert "register_production_unified_t3_route" in source
    assert source.count(invocation) == 1
    assert "assurance_profile=resolve_assurance_profile()" in source


def test_audit_record_marks_only_poc_as_skipped():
    assert assurance_audit_record("poc") == {
        "assurance_profile": "poc",
        "signed_permit_status": "SKIPPED_BY_PROFILE",
        "signed_permit_reason": "poc_profile",
    }
    assert assurance_audit_record("hardened") == {
        "assurance_profile": "hardened",
        "signed_permit_status": "REQUIRED",
        "signed_permit_reason": "hardened_profile",
    }
