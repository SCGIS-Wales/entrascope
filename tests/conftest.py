"""Shared fixtures.

Fixtures are plain functions returning immutable data wherever possible, in
keeping with the functional rules in CLAUDE.md.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from entrascope.config import Config, load_config

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "entrascope"
CONFIG_ROOT = REPO_ROOT / "config"

#: A value that must never appear in any output, log record or rendered table.
SENTINEL_SECRET = "s3ntinel-cl13nt-s3cret-do-not-log"


@pytest.fixture(autouse=True)
def predictable_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Render as though writing to a pipe, whatever the runner has set.

    A continuous integration runner sets COLUMNS, and anything setting
    FORCE_COLOR turns on escape codes, either of which changes what a test
    reads back. Neither says anything about the code being tested.
    """
    for name in ("COLUMNS", "LINES", "FORCE_COLOR", "TERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_COLOR", "1")


@pytest.fixture
def repo_root() -> Path:
    """Return the repository root."""
    return REPO_ROOT


@pytest.fixture
def src_root() -> Path:
    """Return the package source directory."""
    return SRC_ROOT


@pytest.fixture
def config_root() -> Path:
    """Return the configuration directory."""
    return CONFIG_ROOT


@pytest.fixture
def sentinel_secret() -> str:
    """Return the sentinel secret used by the redaction guard."""
    return SENTINEL_SECRET


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures"


def load_fixture(name: str) -> dict[str, Any]:
    """Parse one JSON fixture by file name, without its extension."""
    data = json.loads((FIXTURE_ROOT / f"{name}.json").read_text())
    assert isinstance(data, dict)
    return data


@pytest.fixture
def applications() -> list[dict[str, Any]]:
    """Return the application registration fixtures."""
    return list(load_fixture("applications")["value"])


@pytest.fixture
def service_principals() -> list[dict[str, Any]]:
    """Return the enterprise application fixtures."""
    return list(load_fixture("service_principals")["value"])


@pytest.fixture
def config() -> Config:
    """Return the repository configuration."""
    return load_config()


def source_files() -> list[Path]:
    """Return every Python module in the package."""
    return sorted(SRC_ROOT.glob("*.py"))
