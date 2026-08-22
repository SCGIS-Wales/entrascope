"""Credential contract, file permissions and authentication source tests."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from entrascope.config import Config, load_config
from entrascope.credentials import (
    azure_cli_available,
    check_directory_mode,
    check_file_mode,
    identity_kind,
    read_credential_file,
    read_environment,
    resolution_order,
    resolve_auth,
    resolve_file,
    source_enabled,
    try_source,
)
from entrascope.models import (
    AuthSourceUnavailableError,
    CredentialError,
)
from tests.conftest import SENTINEL_SECRET


def write_credentials(
    home: Path,
    *,
    file_mode: int = 0o600,
    directory_mode: int = 0o700,
    payload: dict[str, str] | None = None,
    config: Config,
) -> Path:
    """Create a credential file under a temporary home directory."""
    path = resolve_file(config.credentials, home)
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = config.credentials.file.keys
    body = (
        payload
        if payload is not None
        else {
            keys["client_id"]: "11111111-1111-1111-1111-111111111111",
            keys["tenant_id"]: "22222222-2222-2222-2222-222222222222",
            keys["secret"]: SENTINEL_SECRET,
        }
    )
    path.write_text(json.dumps(body), encoding="utf-8")
    path.chmod(file_mode)
    path.parent.chmod(directory_mode)
    return path


@pytest.fixture
def config() -> Config:
    """Return the repository configuration."""
    return load_config()


def test_perms_accept(tmp_path: Path, config: Config) -> None:
    """A 0600 file inside a 0700 directory is accepted."""
    write_credentials(tmp_path, config=config)
    assert check_directory_mode(config.credentials, tmp_path).passed
    assert check_file_mode(config.credentials, tmp_path).passed
    credential = read_credential_file(config.credentials, tmp_path)
    assert credential.secret == SENTINEL_SECRET


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666])
def test_perms_reject_group_or_world_readable_file(
    tmp_path: Path, config: Config, mode: int
) -> None:
    """A credential file readable by anyone else is refused."""
    write_credentials(tmp_path, file_mode=mode, config=config)
    result = check_file_mode(config.credentials, tmp_path)
    assert not result.passed
    assert "chmod 0600" in result.remediation
    with pytest.raises(CredentialError) as raised:
        read_credential_file(config.credentials, tmp_path)
    assert "chmod 0600" in str(raised.value)


def test_perms_reject_open_directory(tmp_path: Path, config: Config) -> None:
    """A credential directory open to others is refused."""
    write_credentials(tmp_path, directory_mode=0o755, config=config)
    result = check_directory_mode(config.credentials, tmp_path)
    assert not result.passed
    assert "chmod 0700" in result.remediation
    with pytest.raises(CredentialError):
        read_credential_file(config.credentials, tmp_path)


def test_perms_failure_never_reveals_the_secret(tmp_path: Path, config: Config) -> None:
    """A refusal message carries remediation and no secret."""
    write_credentials(tmp_path, file_mode=0o644, config=config)
    with pytest.raises(CredentialError) as raised:
        read_credential_file(config.credentials, tmp_path)
    assert SENTINEL_SECRET not in str(raised.value)


def test_missing_file_names_the_required_keys(tmp_path: Path, config: Config) -> None:
    """A missing credential file explains what to create."""
    (tmp_path / ".entra").mkdir(mode=0o700)
    result = check_file_mode(config.credentials, tmp_path)
    assert not result.passed
    assert "ClientID" in result.remediation


def test_incomplete_file_names_the_missing_keys(tmp_path: Path, config: Config) -> None:
    """A credential file missing a key is refused by name."""
    write_credentials(tmp_path, payload={"ClientID": "abc"}, config=config)
    with pytest.raises(CredentialError) as raised:
        read_credential_file(config.credentials, tmp_path)
    assert "Secret" in str(raised.value)
    assert "TenantID" in str(raised.value)


def test_credential_repr_cannot_leak_the_secret(tmp_path: Path, config: Config) -> None:
    """Representing a credential shows a placeholder in place of the secret."""
    write_credentials(tmp_path, config=config)
    credential = read_credential_file(config.credentials, tmp_path)
    assert SENTINEL_SECRET not in repr(credential)
    assert "[redacted]" in repr(credential)


def test_auth_source_env(config: Config) -> None:
    """The environment source reads the three ARM variables."""
    names = config.credentials.environment
    environ = {
        names.client_id: "33333333-3333-3333-3333-333333333333",
        names.tenant_id: "44444444-4444-4444-4444-444444444444",
        names.secret: SENTINEL_SECRET,
    }
    credential = read_environment(config.credentials, environ)
    assert credential is not None
    assert credential.client_id.startswith("3333")


def test_auth_source_env_incomplete_is_none(config: Config) -> None:
    """A partially populated environment yields no credential."""
    names = config.credentials.environment
    assert read_environment(config.credentials, {names.client_id: "abc"}) is None


def test_auth_source_env_unavailable_is_explicit(config: Config) -> None:
    """Selecting the environment source without the variables says which to set."""
    with pytest.raises(AuthSourceUnavailableError) as raised:
        try_source("env", config, environ={})
    names = config.credentials.environment
    assert names.client_id in str(raised.value)


def test_auth_source_azure_cli(monkeypatch: pytest.MonkeyPatch, config: Config) -> None:
    """The Azure CLI source yields a delegated identity."""
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: "/usr/bin/az")
    context, credential = try_source("azure-cli", config)
    assert context.source == "azure-cli"
    assert context.identity_kind == "delegated"
    assert credential is not None


def test_auth_source_azure_cli_absent(
    monkeypatch: pytest.MonkeyPatch, config: Config
) -> None:
    """A missing Azure CLI produces remediation naming az login."""
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: None)
    assert not azure_cli_available()
    with pytest.raises(AuthSourceUnavailableError) as raised:
        try_source("azure-cli", config)
    assert "az login" in str(raised.value)


def test_auth_source_default(config: Config) -> None:
    """The default chain is available and reports an unknown identity kind."""
    context, credential = try_source("default", config)
    assert context.source == "default"
    assert credential is not None
    assert identity_kind(config.credentials, "default") == "unknown"


def test_auth_source_file(tmp_path: Path, config: Config) -> None:
    """The file source yields an application identity carrying the tenant."""
    write_credentials(tmp_path, config=config)
    context, credential = try_source("file", config, home=tmp_path)
    assert context.identity_kind == "application"
    assert context.tenant_id is not None
    assert context.tenant_id.startswith("2222")
    assert credential is not None


def test_auth_source_precedence(config: Config) -> None:
    """Resolution order matches the configured order and covers every source."""
    expected = ("file", "env", "azure-cli", "default")
    assert resolution_order(config.credentials) == expected


def test_the_file_and_azure_cli_sources_resolve_automatically(
    config: Config,
) -> None:
    """Somebody who ran az login should not have to name a source.

    The credential file still wins, so an unattended run behaves the same
    whatever else is on the machine. The environment variables and the full
    chain stay off, because either can pick up an identity nobody intended.
    """
    assert source_enabled(config.credentials, "file")
    assert source_enabled(config.credentials, "azure-cli")
    for source in ("env", "default"):
        assert not source_enabled(config.credentials, source)


def test_the_credential_file_still_wins_over_the_azure_cli(
    tmp_path: Path, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unattended run must not change behaviour because somebody signed in."""
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: "/usr/bin/az")
    write_credentials(tmp_path, config=config)
    context, _ = resolve_auth(config, home=tmp_path, environ={})
    assert context.source == "file"


def test_the_azure_cli_answers_when_there_is_no_credential_file(
    tmp_path: Path, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reason for this change: az login and then just run the tool."""
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: "/usr/bin/az")
    context, _ = resolve_auth(config, home=tmp_path, environ={})
    assert context.source == "azure-cli"


def test_explicit_source_overrides_the_gate(
    monkeypatch: pytest.MonkeyPatch, config: Config
) -> None:
    """Naming a disabled source with --auth still selects it."""
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: "/usr/bin/az")
    context, _ = resolve_auth(config, requested="azure-cli")
    assert context.source == "azure-cli"


def test_resolution_reports_every_failure(
    tmp_path: Path, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When nothing works the error names each source tried and why."""
    monkeypatch.setattr("entrascope.credentials.shutil.which", lambda _: None)
    empty: Mapping[str, str] = {}
    with pytest.raises(CredentialError) as raised:
        resolve_auth(config, home=tmp_path, environ=empty)
    message = str(raised.value)
    assert "Tried: file, azure-cli" in message
    assert "does not exist" in message
    assert "az login" in message


def test_resolution_falls_through_to_the_first_working_source(
    tmp_path: Path, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the file source enabled and present, resolution picks it."""
    write_credentials(tmp_path, config=config)
    context, _ = resolve_auth(config, home=tmp_path, environ={})
    assert context.source == "file"


def test_environment_is_read_from_the_process_when_not_injected(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Omitting the environment argument reads the real process environment."""
    names = config.credentials.environment
    monkeypatch.setenv(names.client_id, "55555555-5555-5555-5555-555555555555")
    monkeypatch.setenv(names.tenant_id, "66666666-6666-6666-6666-666666666666")
    monkeypatch.setenv(names.secret, SENTINEL_SECRET)
    credential = read_environment(config.credentials)
    assert credential is not None
    assert credential.tenant_id.startswith("6666")
    assert os.environ[names.client_id].startswith("5555")


def test_no_secret_reaches_a_log_record(
    tmp_path: Path, config: Config, caplog: pytest.LogCaptureFixture
) -> None:
    """Resolving an identity logs nothing that carries the secret."""
    write_credentials(tmp_path, config=config)
    with caplog.at_level("DEBUG"):
        resolve_auth(config, requested="file", home=tmp_path)
    payload: Any = caplog.text
    assert SENTINEL_SECRET not in payload


def test_the_file_that_was_opened_is_the_file_that_was_checked(
    tmp_path: Path, config: Config
) -> None:
    """Checking a path and then opening it leaves a gap.

    The mode is taken from the open descriptor, so what was checked and what
    was read cannot be two different files.
    """
    from entrascope.credentials import read_checked

    path = write_credentials(tmp_path, config=config)
    assert SENTINEL_SECRET in read_checked(path, config.credentials)
    path.chmod(0o644)
    with pytest.raises(CredentialError, match="chmod 0600"):
        read_checked(path, config.credentials)
