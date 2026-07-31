import sys
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hexstrike_t3_poc import register_t3_poc_routes  # noqa: E402
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
