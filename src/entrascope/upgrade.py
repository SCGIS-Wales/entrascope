"""Knowing there is a newer version, and getting it.

Two rules govern the version check. It must never slow a command down, and it
must never stop one working. So it is cached for a day, it has a short timeout,
it is skipped whenever the output is going to a machine rather than a person,
and every failure is silent.

Upgrading is separate, because how a package is upgraded depends entirely on
how it was installed, and getting that wrong on somebody's system Python is
worse than not offering it at all.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal, NamedTuple

from entrascope import __version__
from entrascope.config import Config, UpgradeSettings
from entrascope.http import build_session, get_json
from entrascope.logger import get_logger
from entrascope.models import EntrascopeError

log = get_logger(__name__)

#: How the running copy was installed, which decides how to upgrade it.
Installation = Literal["virtualenv", "pipx", "uv-tool", "externally-managed", "system"]

#: The file a distribution ships to say the environment is managed by something
#: other than pip. Ignoring it is how a Homebrew Python gets broken.
EXTERNALLY_MANAGED = "EXTERNALLY-MANAGED"


class Release(NamedTuple):
    """The newest published version, where to read about it, and its files."""

    version: str
    url: str
    published: str = ""
    #: The files published with the release, wheel first. Somebody whose Python
    #: is managed by something else cannot run the upgrade and can still fetch
    #: the file, and somebody behind a proxy that blocks the index needs the
    #: address to hand.
    files: tuple[str, ...] = ()

    def newer_than(self, running: str) -> bool:
        """Return whether this release is ahead of the version running."""
        return parse_version(self.version) > parse_version(running)


def parse_version(value: str) -> tuple[int, ...]:
    """Parse a version for comparison, ignoring anything after the numbers."""
    cleaned = value.strip().lstrip("vV").split("+")[0].split("-")[0]
    parts: list[int] = []
    for piece in cleaned.split("."):
        digits = "".join(character for character in piece if character.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def cache_path(config: Config) -> Path:
    """Return where the last answer from the release feed is kept."""
    return Path(config.logging.update_check.cache_file).expanduser()


def read_cache(config: Config) -> tuple[Release | None, bool]:
    """Return the cached release and whether it is still fresh."""
    settings = config.logging.update_check
    path = cache_path(config)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError, ValueError:
        return None, False
    if not isinstance(payload, dict):
        return None, False
    try:
        fetched = float(payload.get("fetched_at", 0))
    except TypeError, ValueError:
        return None, False
    fresh = (time.time() - fetched) < settings.interval_hours * 3600
    version = str(payload.get("version", ""))
    if not version:
        return None, fresh
    files = payload.get("files")
    return (
        Release(
            version=version,
            url=str(payload.get("url", "")),
            # Remembered with the rest, because the addresses are half of what
            # somebody asking about a release wants and refetching them would
            # defeat the point of a cache.
            files=tuple(str(item) for item in files) if isinstance(files, list) else (),
        ),
        fresh,
    )


def write_cache(config: Config, release: Release) -> None:
    """Remember the answer, so tomorrow's command asks nothing of the network."""
    path = cache_path(config)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "version": release.version,
                    "url": release.url,
                    "files": list(release.files),
                    "fetched_at": time.time(),
                }
            ),
            encoding="utf-8",
        )
    except OSError as error:
        log.debug("could not write the release cache: %s", error)


def fetch_release(config: Config) -> Release | None:
    """Ask the release feed for the newest version.

    Any failure is a shrug. Not knowing whether there is a newer version is a
    great deal less important than the command the engineer actually ran.
    """
    settings = config.logging.update_check
    releases = config.endpoints.releases
    timeouts = config.retry.http.model_copy(
        update={
            "connect_timeout_seconds": settings.timeout_seconds,
            "read_timeout_seconds": settings.timeout_seconds,
        }
    )
    quick = config.model_copy(
        update={"retry": config.retry.model_copy(update={"http": timeouts})}
    )
    session = build_session(quick)
    try:
        body = get_json(session, releases.latest_url, quick, source="releases")
    except Exception as error:
        log.debug("could not read the release feed: %r", error)
        return None
    finally:
        session.close()
    tag = str(body.get("tag_name") or "")
    if not tag:
        return None
    release = Release(
        version=tag,
        url=str(body.get("html_url") or releases.page_url),
        files=published_files(body),
    )
    write_cache(config, release)
    return release


def published_files(body: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the download addresses of a release, the wheel first."""
    assets = body.get("assets")
    if not isinstance(assets, Sequence):
        return ()
    addresses = [
        str(asset.get("browser_download_url"))
        for asset in assets
        if isinstance(asset, Mapping) and asset.get("browser_download_url")
    ]
    return tuple(sorted(addresses, key=lambda name: not name.endswith(".whl")))


def check_disabled(config: Config, environ: dict[str, str] | None = None) -> bool:
    """Return whether the version check has been switched off."""
    settings = config.logging.update_check
    source = os.environ if environ is None else environ
    return not settings.enabled or bool(source.get(settings.disable_variable))


def newer_release(
    config: Config, *, force: bool = False, environ: dict[str, str] | None = None
) -> Release | None:
    """Return a newer release if there is one, using the cache unless forced.

    Nothing this function can meet is worth failing a command over. A corrupt
    cache, a proxy answering with a sign in page, a clock that makes a
    timestamp nonsense, a release tag in a shape nobody expected: each of them
    means the same thing, which is that we do not know, and not knowing is a
    great deal less important than the command the engineer actually ran. So
    the whole of it sits behind one boundary rather than a list of the failures
    somebody thought of.
    """
    try:
        return _newer_release(config, force=force, environ=environ)
    except Exception as error:
        log.debug("the version check failed and was ignored: %r", error)
        return None


def _newer_release(
    config: Config, *, force: bool, environ: dict[str, str] | None
) -> Release | None:
    """Work out whether a newer release exists. Never called directly."""
    release = _latest_release(config, force=force, environ=environ)
    if release is None or not release.newer_than(__version__):
        return None
    return release


def latest_release(
    config: Config, *, force: bool = False, environ: dict[str, str] | None = None
) -> Release | None:
    """Return the newest published release, whether or not it is ahead.

    Somebody asking what is published wants the answer even when they already
    have it, because the answer includes where the files are.
    """
    try:
        return _latest_release(config, force=force, environ=environ)
    except Exception as error:
        log.debug("the version check failed and was ignored: %r", error)
        return None


def _latest_release(
    config: Config, *, force: bool, environ: dict[str, str] | None
) -> Release | None:
    """Read the newest published release. Never called directly."""
    if check_disabled(config, environ) and not force:
        return None
    cached, fresh = read_cache(config)
    return cached if fresh and not force else (fetch_release(config) or cached)


def upgrade_notice(release: Release) -> str:
    """Return the one line an engineer sees when a newer version exists."""
    return (
        f"A newer entrascope is available: {release.version}, running "
        f"{__version__}. Upgrade with: entrascope upgrade"
    )


def running_from() -> Path:
    """Return the directory the running copy is installed into."""
    return Path(sys.prefix)


def externally_managed() -> Path | None:
    """Return the marker file if this environment is managed by something else.

    A Homebrew or distribution Python ships this to say that installing into it
    with pip is a way to break the operating system's own tooling.
    """
    import sysconfig

    for name in ("stdlib", "platstdlib", "purelib"):
        directory = sysconfig.get_path(name)
        if not directory:
            continue
        marker = Path(directory).parent / EXTERNALLY_MANAGED
        if marker.is_file():
            return marker
        marker = Path(directory) / EXTERNALLY_MANAGED
        if marker.is_file():
            return marker
    return None


def installation_kind() -> Installation:
    """Work out how this copy was installed, which decides how to upgrade it."""
    prefix = str(running_from())
    if "pipx" in prefix:
        return "pipx"
    if f"{os.sep}uv{os.sep}tools" in prefix or f"{os.sep}uv-tools{os.sep}" in prefix:
        return "uv-tool"
    if sys.prefix != sys.base_prefix:
        return "virtualenv"
    if externally_managed() is not None:
        return "externally-managed"
    return "system"


def upgrade_command(
    kind: Installation, package: str, *, break_system_packages: bool = False
) -> list[str]:
    """Return the command that upgrades this installation.

    Always through this interpreter rather than a bare pip, because the pip on
    the path is frequently not the one that owns this installation, and on many
    systems there is no command called pip at all.
    """
    if kind == "pipx":
        return ["pipx", "upgrade", package]
    if kind == "uv-tool":
        return ["uv", "tool", "upgrade", package]
    command = [sys.executable, "-m", "pip", "install", "--upgrade", "--no-cache-dir"]
    if kind == "externally-managed" and break_system_packages:
        command.append("--break-system-packages")
    command.append(package)
    return command


def refuse_externally_managed(package: str, marker: Path) -> str:
    """Explain why this will not upgrade a managed environment on its own."""
    return (
        f"This Python is managed by something other than pip, which said so in "
        f"{marker}.\n"
        "  Upgrading into it can break the tooling that owns it, so entrascope "
        "will not do that unless you ask.\n"
        "  The safe ways, best first:\n"
        f"    pipx upgrade {package}\n"
        f"    uv tool upgrade {package}\n"
        f"    python3 -m venv ~/.venvs/entrascope && "
        f"~/.venvs/entrascope/bin/pip install --upgrade {package}\n"
        "  Or, knowing what it may break:\n"
        "    entrascope upgrade --break-system-packages"
    )


def run_upgrade(
    config: Config,
    *,
    break_system_packages: bool = False,
    dry_run: bool = False,
) -> tuple[list[str], str]:
    """Upgrade the running installation, or explain why it will not.

    Returns the command and whatever it printed, so the caller can show both.
    """
    package = config.endpoints.releases.package_name
    kind = installation_kind()
    if kind == "externally-managed" and not break_system_packages:
        marker = externally_managed()
        raise EntrascopeError(
            refuse_externally_managed(package, marker or Path(EXTERNALLY_MANAGED))
        )
    command = upgrade_command(
        kind, package, break_system_packages=break_system_packages
    )
    if dry_run:
        return command, ""
    return command, install(command, config.retry.upgrade)


def install(command: Sequence[str], settings: UpgradeSettings) -> str:
    """Run the installer, trying again when it fails.

    The installer reaches a package index across the network, and an index that
    is briefly unreachable should cost a wait rather than a failed upgrade.
    Installing is idempotent, so trying again is safe.

    An installer that will not start at all is a different thing. No amount of
    waiting produces a program that is not there, so that is reported at once.
    """
    attempts = max(1, settings.attempts)
    output = ""
    for attempt in range(1, attempts + 1):
        try:
            # framework contract: upgrading a package means running the
            # installer, and there is no library interface for that. The
            # command is built here from a fixed shape, never from anything an
            # engineer typed.
            completed = subprocess.run(
                list(command),
                capture_output=True,
                text=True,
                check=False,
                timeout=settings.timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            output = f"the installer did not finish in time: {error}"
        except (OSError, subprocess.SubprocessError) as error:
            raise EntrascopeError(
                f"Could not run the upgrade. {' '.join(command)}\n  {error}"
            ) from error
        else:
            output = (completed.stdout or "") + (completed.stderr or "")
            if completed.returncode == 0:
                return output
        if attempt < attempts:
            log.warning(
                "the upgrade did not succeed on attempt %s of %s, trying again "
                "in %s seconds",
                attempt,
                attempts,
                settings.wait_seconds,
            )
            time.sleep(settings.wait_seconds)
    raise EntrascopeError(
        f"The upgrade failed after {attempts} attempts.\n"
        f"  {' '.join(command)}\n{tail(output)}"
    )


def tail(output: str, lines: int = 12) -> str:
    """Return the last few lines of a command's output."""
    kept = [line for line in output.splitlines() if line.strip()][-lines:]
    return "\n".join(f"  {line}" for line in kept)


def describe_installation(config: Config) -> dict[str, Any]:
    """Describe how this copy was installed and what would upgrade it."""
    kind = installation_kind()
    package = config.endpoints.releases.package_name
    # The marker belongs to the base interpreter, so it is only the reason for
    # anything when this is not a virtual environment of its own.
    marker = externally_managed() if kind == "externally-managed" else None
    return {
        "running_version": __version__,
        "installation": kind,
        "interpreter": sys.executable,
        "prefix": str(running_from()),
        "externally_managed_marker": str(marker) if marker else None,
        "upgrade_command": " ".join(upgrade_command(kind, package)),
    }
