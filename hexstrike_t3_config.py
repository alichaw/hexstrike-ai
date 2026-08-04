"""Protected T3 JSON loading shared by non-root HexStrike services."""

from __future__ import annotations

import grp
import json
import os
import stat
from pathlib import Path
from typing import Any


def load_protected_json(path: Path) -> dict[str, Any]:
    """Read one root-managed, service-group-readable regular JSON file."""
    label = path.name
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise ValueError(
            f"protected_configuration_missing:{label}:expected=root:hexstrike:0640"
        ) from exc
    except PermissionError as exc:
        raise ValueError(
            f"protected_configuration_unreadable:{label}:expected=root:hexstrike:0640"
        ) from exc
    except OSError as exc:
        raise ValueError(f"protected_configuration_open_failed:{label}") from exc

    try:
        info = os.fstat(descriptor)
        try:
            group_name = grp.getgrgid(info.st_gid).gr_name
        except KeyError:
            group_name = ""
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or group_name != "hexstrike"
            or stat.S_IMODE(info.st_mode) != 0o640
        ):
            raise ValueError(
                f"protected_configuration_unsafe_metadata:{label}:"
                "expected=root:hexstrike:0640"
            )
        try:
            with os.fdopen(descriptor, encoding="utf-8") as handle:
                descriptor = -1
                value = json.load(handle)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"protected_configuration_json_invalid:{label}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise ValueError(f"protected_configuration_root_invalid:{label}")
    return value
