from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hexstrike_t3_authorization import (  # noqa: E402
    consume_authorization_id,
    validate_authorization_id,
)

NOW = 1_800_000_000


def authorization(tag="a1", fill="a", issued_at=NOW):
    return f"{issued_at:08x}{tag}{fill * 30}"


def test_stage_binding_and_expiry_are_fail_closed():
    selected = authorization()
    assert validate_authorization_id(selected, "T3-A", clock=lambda: NOW) == selected
    with pytest.raises(ValueError, match="binding"):
        validate_authorization_id(selected, "T3-B", clock=lambda: NOW)
    with pytest.raises(ValueError, match="expired"):
        validate_authorization_id(
            authorization(issued_at=NOW - 60), "T3-A", clock=lambda: NOW
        )
    with pytest.raises(ValueError, match="expired"):
        validate_authorization_id(
            authorization(issued_at=NOW + 6), "T3-A", clock=lambda: NOW
        )


def test_concurrent_and_post_restart_reuse_has_one_consumer(tmp_path):
    database = tmp_path / "spent.sqlite3"
    selected = authorization()

    def consume():
        try:
            consume_authorization_id(database, selected, "T3-A")
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(lambda _: consume(), range(4)))
    assert sum(outcomes) == 1
    with pytest.raises(ValueError, match="replayed"):
        consume_authorization_id(database, selected, "T3-A")
