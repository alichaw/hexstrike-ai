"""Strict protected assurance-profile selection for HexStrike T3 routes."""

from __future__ import annotations

import os

ACCEPTED_PROFILES = frozenset({"poc", "hardened"})


def resolve_assurance_profile(environment=None) -> str:
    selected_environment = os.environ if environment is None else environment
    value = selected_environment.get("HEXSTRIKE_ASSURANCE_PROFILE")
    if value not in ACCEPTED_PROFILES:
        raise RuntimeError(
            "HEXSTRIKE_ASSURANCE_PROFILE must be explicitly poc or hardened"
        )
    return value


def assurance_audit_record(profile: str) -> dict[str, object]:
    if profile not in ACCEPTED_PROFILES:
        raise ValueError("assurance profile invalid")
    skipped = profile == "poc"
    return {
        "assurance_profile": profile,
        "signed_permit_status": "SKIPPED_BY_PROFILE" if skipped else "REQUIRED",
        "signed_permit_reason": "poc_profile" if skipped else "hardened_profile",
    }
