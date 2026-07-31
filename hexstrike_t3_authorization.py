"""Persistent, atomic PoC authorization-ID validation and consumption."""

from __future__ import annotations

import re
import sqlite3
import time
from pathlib import Path

AUTHORIZATION_TTL_SECONDS = 60
_STAGE_TAGS = {"T3-A": "a1", "T3-B": "b1", "T3-C": "c1"}
_FORMAT = re.compile(r"^(?P<issued>[a-f0-9]{8})(?P<tag>[a-f0-9]{2})[a-f0-9]{30}$")


def validate_authorization_id(
    value: object,
    stage: str,
    *,
    clock=time.time,
) -> str:
    expected_tag = _STAGE_TAGS.get(stage)
    if expected_tag is None:
        raise ValueError("authorization_stage_invalid")
    if not isinstance(value, str):
        raise ValueError("authorization_invalid")
    matched = _FORMAT.fullmatch(value)
    if matched is None or matched.group("tag") != expected_tag:
        raise ValueError("authorization_binding_invalid")
    issued_at = int(matched.group("issued"), 16)
    now = int(clock())
    if issued_at > now + 5 or now >= issued_at + AUTHORIZATION_TTL_SECONDS:
        raise ValueError("authorization_expired")
    return value


def consume_authorization_id(path: Path, authorization_id: str, stage: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=5, isolation_level="IMMEDIATE") as database:
        database.execute(
            "CREATE TABLE IF NOT EXISTS spent_authorizations "
            "(authorization_id TEXT PRIMARY KEY, stage TEXT NOT NULL, "
            "consumed_at INTEGER NOT NULL)"
        )
        try:
            database.execute(
                "INSERT INTO spent_authorizations VALUES (?, ?, ?)",
                (authorization_id, stage, int(time.time())),
            )
            database.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("authorization_replayed") from exc
