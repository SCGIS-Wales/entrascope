"""Version check and upgrade tests.

Two rules are tested harder than anything else: the check never slows a command
down or stops it working, and the upgrade never installs into a Python that
something else manages without being asked.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
import responses

from entrascope import __version__
from entrascope.config import Config
from entrascope.models import EntrascopeError
from entrascope.upgrade import (
    Release,
    cache_path,
    check_disabled,
    describe_installation,
    fetch_release,
    installation_kind,
    newer_release,
    parse_version,
    read_cache,
    refuse_externally_managed,
    run_upgrade,
    tail,
    upgrade_command,
    upgrade_notice,
    write_cache,
)

FEED = "https://api.github.com/repos/SCGIS-Wales/entrascope/releases/latest"


@pytest.fixture
def cached_in(tmp_path: Path, config: Config) -> Config:
    """Return configuration whose release cache is inside a temporary directory."""
    update = config.logging.update_check.model_copy(
        update={"cache_file": str(tmp_path / "latest.json")}
    )
    return config.model_copy(
        update={"logging": config.logging.model_copy(update={"update_check": update})}
    )


def test_versions_compare_by_number_not_by_text() -> None:
    """Ten is after nine, whatever a string comparison thinks."""
    assert parse_version("v0.1.10") > parse_version("0.1.9")
    assert parse_version("1.0.0") > parse_version("0.99.99")
    assert parse_version("0.1.6") == parse_version("v0.1.6")


def test_a_prerelease_suffix_does_not_confuse_the_comparison() -> None:
    """Anything after the numbers is ignored rather than misread."""
    assert parse_version("0.2.0-rc1") == (0, 2, 0)
    assert parse_version("nonsense") == (0,)


def test_a_release_knows_whether_it_is_newer() -> None:
    """The whole point of the check."""
    assert Release(version="v9.9.9", url="").newer_than(__version__)
    assert not Release(version="v0.0.1", url="").newer_than(__version__)


@responses.activate
def test_the_feed_is_read_and_remembered(cached_in: Config) -> None:
    """One answer a day, so tomorrow's command asks nothing of the network."""
    responses.add(
        responses.GET,
        FEED,
        json={"tag_name": "v9.9.9", "html_url": "https://example.invalid/notes"},
        status=200,
    )
    release = fetch_release(cached_in)
    assert release is not None
    assert release.version == "v9.9.9"
    cached, fresh = read_cache(cached_in)
    assert fresh
    assert cached is not None
    assert cached.version == "v9.9.9"


@responses.activate
def test_a_fresh_cache_makes_no_request(cached_in: Config) -> None:
    """A version check that costs a round trip every command is a tax."""
    write_cache(cached_in, Release(version="v9.9.9", url="https://example.invalid"))
    release = newer_release(cached_in)
    assert release is not None
    assert not responses.calls


@responses.activate
def test_a_stale_cache_is_refreshed(cached_in: Config) -> None:
    """After the interval it asks again."""
    path = cache_path(cached_in)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": "v0.0.1", "url": "", "fetched_at": time.time() - 90_000})
    )
    responses.add(responses.GET, FEED, json={"tag_name": "v9.9.9"}, status=200)
    release = newer_release(cached_in)
    assert release is not None
    assert release.version == "v9.9.9"
    assert len(responses.calls) == 1


@responses.activate
def test_a_network_failure_is_a_shrug(cached_in: Config) -> None:
    """Not knowing whether there is a newer version must never stop anything."""
    import requests

    responses.add(responses.GET, FEED, body=requests.exceptions.ConnectionError("no"))
    assert fetch_release(cached_in) is None
    assert newer_release(cached_in) is None


@responses.activate
def test_a_feed_with_no_tag_is_ignored(cached_in: Config) -> None:
    """An answer that says nothing is not an answer."""
    responses.add(responses.GET, FEED, json={"nothing": True}, status=200)
    assert fetch_release(cached_in) is None


@responses.activate
def test_an_unreadable_cache_is_ignored(cached_in: Config) -> None:
    """A corrupted cache file must not break the command that read it."""
    path = cache_path(cached_in)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json")
    responses.add(responses.GET, FEED, json={"tag_name": "v9.9.9"}, status=200)
    assert newer_release(cached_in) is not None


def test_the_check_can_be_switched_off(config: Config) -> None:
    """Somebody who does not want it asked should not have it asked."""
    variable = config.logging.update_check.disable_variable
    assert check_disabled(config, {variable: "1"})
    assert not check_disabled(config, {})
    assert newer_release(config, environ={variable: "1"}) is None


def test_the_same_version_is_not_announced(cached_in: Config) -> None:
    """A notice that appears when nothing is wrong is a notice nobody reads."""
    write_cache(cached_in, Release(version=__version__, url=""))
    assert newer_release(cached_in) is None


def test_the_notice_says_both_versions_and_what_to_do() -> None:
    """Told what is new, what is running, and the command."""
    notice = upgrade_notice(Release(version="v9.9.9", url=""))
    assert "v9.9.9" in notice
    assert __version__ in notice
    assert "entrascope upgrade" in notice


def test_the_upgrade_goes_through_this_interpreter() -> None:
    """The pip on the path frequently is not the one that owns this install.

    On many systems there is no command called pip at all, which is exactly
    what somebody meets when they follow an instruction that says to run it.
    """
    import sys

    command = upgrade_command("virtualenv", "entrascope")
    assert command[0] == sys.executable
    assert command[1:4] == ["-m", "pip", "install"]
    assert command[0] != "pip"


def test_each_kind_of_install_gets_its_own_command() -> None:
    """How a package is upgraded depends entirely on how it was installed."""
    assert upgrade_command("pipx", "entrascope")[:2] == ["pipx", "upgrade"]
    assert upgrade_command("uv-tool", "entrascope")[:3] == ["uv", "tool", "upgrade"]
    managed = upgrade_command(
        "externally-managed", "entrascope", break_system_packages=True
    )
    assert "--break-system-packages" in managed
    assert "--break-system-packages" not in upgrade_command(
        "externally-managed", "entrascope"
    )


def test_a_managed_python_is_refused_until_asked(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Installing into it can break the tooling that owns it."""
    monkeypatch.setattr(
        "entrascope.upgrade.installation_kind", lambda: "externally-managed"
    )
    monkeypatch.setattr(
        "entrascope.upgrade.externally_managed", lambda: Path("/somewhere/marker")
    )
    with pytest.raises(EntrascopeError) as raised:
        run_upgrade(config)
    message = str(raised.value)
    assert "pipx upgrade entrascope" in message
    assert "--break-system-packages" in message
    assert "/somewhere/marker" in message


def test_the_refusal_offers_the_safe_ways_first() -> None:
    """The order matters, because the first one somebody reads is the one they run."""
    message = refuse_externally_managed("entrascope", Path("/marker"))
    assert message.index("pipx") < message.index("break-system-packages")
    assert message.index("venv") < message.index("break-system-packages")


def test_a_failed_upgrade_says_what_it_ran(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure nobody can reproduce is a failure nobody can fix."""

    class Completed:
        returncode = 1
        stdout = "one\ntwo\n"
        stderr = "it went wrong\n"

    monkeypatch.setattr("entrascope.upgrade.installation_kind", lambda: "virtualenv")
    monkeypatch.setattr(
        "entrascope.upgrade.subprocess.run", lambda *a, **k: Completed()
    )
    with pytest.raises(EntrascopeError) as raised:
        run_upgrade(config)
    assert "it went wrong" in str(raised.value)
    assert "pip install --upgrade" in str(raised.value)


def test_an_upgrade_that_cannot_start_says_so(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing installer is a sentence, not a traceback."""

    def explode(*args: Any, **kwargs: Any) -> None:
        raise OSError("no such file")

    monkeypatch.setattr("entrascope.upgrade.installation_kind", lambda: "virtualenv")
    monkeypatch.setattr("entrascope.upgrade.subprocess.run", explode)
    with pytest.raises(EntrascopeError, match="Could not run the upgrade"):
        run_upgrade(config)


def test_a_dry_run_changes_nothing(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Showing the command is the point of asking for it."""

    def explode(*args: Any, **kwargs: Any) -> None:  # pragma: no cover
        raise AssertionError("nothing should have been run")

    monkeypatch.setattr("entrascope.upgrade.installation_kind", lambda: "virtualenv")
    monkeypatch.setattr("entrascope.upgrade.subprocess.run", explode)
    command, output = run_upgrade(config, dry_run=True)
    assert "install" in command
    assert output == ""


def test_the_installation_describes_itself(config: Config) -> None:
    """Somebody asking how to upgrade needs to know what they are running."""
    report = describe_installation(config)
    assert report["running_version"] == __version__
    assert report["installation"] == installation_kind()
    assert "entrascope" in report["upgrade_command"]


def test_output_is_trimmed_to_the_end() -> None:
    """The last few lines of an installer are the ones that say what happened."""
    trimmed = tail("\n".join(str(number) for number in range(50)), lines=3)
    assert trimmed.splitlines() == ["  47", "  48", "  49"]


@pytest.mark.parametrize(
    "target",
    [
        "entrascope.upgrade.check_disabled",
        "entrascope.upgrade.read_cache",
        "entrascope.upgrade.fetch_release",
    ],
)
def test_nothing_the_check_touches_can_fail_a_command(
    config: Config, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    """Every step is behind the same boundary.

    A corrupt cache, a proxy answering with a sign in page, a clock that makes
    a timestamp nonsense: each means the same thing, which is that we do not
    know, and not knowing must never stop the command that was actually run.
    """

    def explode(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("something nobody thought of")

    monkeypatch.setattr(target, explode)
    assert newer_release(config) is None


def test_a_cache_holding_the_wrong_shape_is_ignored(cached_in: Config) -> None:
    """A file that is valid JSON and nonsense is still nonsense."""
    path = cache_path(cached_in)
    path.parent.mkdir(parents=True, exist_ok=True)
    for contents in ('"a string"', "[1, 2, 3]", '{"fetched_at": "not a number"}'):
        path.write_text(contents)
        assert read_cache(cached_in) == (None, False)


def test_a_release_tag_in_an_unexpected_shape_is_survivable(
    cached_in: Config,
) -> None:
    """A tag nobody expected is not a reason to fail."""
    write_cache(cached_in, Release(version="not a version at all", url=""))
    assert newer_release(cached_in) is None


@responses.activate
def test_a_feed_answering_with_a_sign_in_page_is_ignored(cached_in: Config) -> None:
    """A captive portal answers everything, including this."""
    responses.add(
        responses.GET,
        FEED,
        body="<html>sign in</html>",
        status=200,
        content_type="text/html",
    )
    assert fetch_release(cached_in) is None


@responses.activate
def test_a_feed_answering_with_an_error_is_ignored(cached_in: Config) -> None:
    """Rate limited, moved, or down. None of it matters here."""
    responses.add(responses.GET, FEED, json={"message": "rate limited"}, status=403)
    assert fetch_release(cached_in) is None


def test_an_unwritable_cache_does_not_stop_the_answer(
    cached_in: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read only home directory is somebody's real situation."""

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise OSError("read only file system")

    monkeypatch.setattr(Path, "write_text", refuse)
    write_cache(cached_in, Release(version="v9.9.9", url=""))
