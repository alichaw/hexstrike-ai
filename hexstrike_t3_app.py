"""Minimal loopback-only application for the unified T3 research PoC."""

from __future__ import annotations

import os

from flask import Flask

from hexstrike_t3_execution import register_production_unified_t3_route
from hexstrike_t3_profile import resolve_assurance_profile


def create_app() -> Flask:
    app = Flask("hexstrike-unified-t3-poc")
    register_production_unified_t3_route(
        app,
        assurance_profile=resolve_assurance_profile(),
    )
    return app


app = create_app()


if __name__ == "__main__":
    host = os.environ.get("HEXSTRIKE_HOST")
    if host != "127.0.0.1":
        raise SystemExit("loopback_host_required")
    app.run(host=host, port=int(os.environ.get("HEXSTRIKE_PORT", "8888")), debug=False)
