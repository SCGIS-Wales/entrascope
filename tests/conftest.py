"""Shared fixtures.

Fixtures are plain functions returning immutable data wherever possible, in
keeping with the functional rules in CLAUDE.md.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "entrascope"
CONFIG_ROOT = REPO_ROOT / "config"

#: A value that must never appear in any output, log record or rendered table.
SENTINEL_SECRET = "s3ntinel-cl13nt-s3cret-do-not-log"


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


def source_files() -> list[Path]:
    """Return every Python module in the package."""
    return sorted(SRC_ROOT.glob("*.py"))
