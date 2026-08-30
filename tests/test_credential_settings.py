"""Where credentials are read from, and saying so.

Three things that used to be true only by editing a file by hand: the
credential location is settable, a missing file offers what is beside it, and
every run says what it is about to authenticate as.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from entrascope.cli import cli, worth_offering_a_file
from entrascope.config import (
    Config,
    clear_cache,
    load_config,
    write_user_config,
)
from entrascope.credentials import posture
from entrascope.models import CredentialPosture
from entrascope.render import credential_banner

CREDENTIALS_FILE = "credentials.yaml"


@pytest.fixture
def own_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the engineer's own configuration directory at a temporary one."""
    root = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root))
    monkeypatch.delenv("ENTRASCOPE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("ENTRASCOPE_CREDENTIAL_FILE", raising=False)
    clear_cache()
    yield root / "entrascope"
    clear_cache()


def credential_directory(tmp_path: Path, *names: str) -> Path:
    """Create a credential directory holding some files."""
    directory = tmp_path / "creds"
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    for name in names:
        path = directory / name
        path.write_text(
            json.dumps({"ClientID": "a", "TenantID": "b", "Secret": "c"}),
            encoding="utf-8",
        )
        path.chmod(0o600)
    return directory


def run(*arguments: str, **kwargs: Any) -> Any:
    """Invoke the command line the way a person would."""
    return CliRunner().invoke(cli, list(arguments), obj={}, **kwargs)


def test_the_settings_are_shown_with_no_options(own_config: Path) -> None:
    """Reading what is in force must not change what is in force."""
    result = run("config", "credentials")
    assert result.exit_code == 0
    assert "directory" in result.output
    assert "certificate" in result.output
    assert not own_config.exists()


def test_a_directory_can_be_set_and_takes_effect(
    own_config: Path, tmp_path: Path
) -> None:
    """The ask that started this: the location was not settable at all."""
    directory = credential_directory(tmp_path, "prod.json")
    result = run("config", "credentials", "--directory", str(directory))
    assert result.exit_code == 0
    assert str(directory) in result.output
    assert load_config().credentials.file.directory == str(directory)


def test_a_file_can_be_set_and_the_directory_is_kept(
    own_config: Path, tmp_path: Path
) -> None:
    """Setting one must not quietly drop the other, which merging is for."""
    directory = credential_directory(tmp_path, "staging.json")
    run("config", "credentials", "--directory", str(directory))
    result = run("config", "credentials", "--file", "staging.json")
    assert result.exit_code == 0
    settings = load_config().credentials.file
    assert settings.directory == str(directory)
    assert settings.filename == "staging.json"


def test_what_is_written_is_only_what_changed(own_config: Path, tmp_path: Path) -> None:
    """A file holding one key keeps working when a release adds another."""
    directory = credential_directory(tmp_path)
    run("config", "credentials", "--directory", str(directory))
    written = (own_config / CREDENTIALS_FILE).read_text()
    assert "directory" in written
    # Everything else still comes from the defaults underneath.
    assert "identity_kind" not in written
    assert load_config().credentials.sources.enabled["file"]


def test_forgetting_goes_back_to_the_defaults(own_config: Path, tmp_path: Path) -> None:
    """A setting nobody can undo is a setting nobody should make."""
    directory = credential_directory(tmp_path)
    run("config", "credentials", "--directory", str(directory))
    shipped = load_config().credentials
    result = run("config", "credentials", "--forget")
    assert result.exit_code == 0
    assert not (own_config / CREDENTIALS_FILE).exists()
    assert load_config().credentials.file.directory != shipped.file.directory


def test_forgetting_nothing_says_so(own_config: Path) -> None:
    """Rather than reporting a removal that did not happen."""
    result = run("config", "credentials", "--forget")
    assert result.exit_code == 0
    assert "Nothing of your own" in result.output


def test_a_certificate_readable_by_others_is_refused(
    own_config: Path, tmp_path: Path
) -> None:
    """Storing a path to a key anybody can read would store a problem."""
    certificate = tmp_path / "app.pem"
    certificate.write_text("x", encoding="utf-8")
    certificate.chmod(0o644)
    result = run("config", "credentials", "--certificate", str(certificate))
    assert result.exit_code != 0
    assert "chmod 0600" in result.output


def test_a_certificate_is_stored_when_it_is_safe(
    own_config: Path, tmp_path: Path
) -> None:
    """And then fills in for any credential file naming none of its own."""
    certificate = tmp_path / "app.pem"
    certificate.write_text("x", encoding="utf-8")
    certificate.chmod(0o600)
    result = run("config", "credentials", "--certificate", str(certificate))
    assert result.exit_code == 0
    assert load_config().credentials.certificate.default_path == str(certificate)


def test_the_missing_file_names_what_is_beside_it(
    own_config: Path, tmp_path: Path
) -> None:
    """Naming them is what makes choosing one possible."""
    directory = credential_directory(tmp_path, "prod.json", "staging.json")
    result = run("config", "credentials", "--directory", str(directory))
    assert "prod.json, staging.json" in result.output
    assert "--choose" in result.output


def test_choosing_with_nothing_there_says_so(own_config: Path, tmp_path: Path) -> None:
    """An empty directory is a different problem from a missing file."""
    directory = credential_directory(tmp_path)
    run("config", "credentials", "--directory", str(directory))
    result = run("config", "credentials", "--choose")
    assert "no credential files" in result.output


def test_choosing_from_a_numbered_list_remembers_the_answer(
    own_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The chooser needs a terminal. A numbered list works wherever a prompt does."""
    directory = credential_directory(tmp_path, "prod.json", "staging.json")
    run("config", "credentials", "--directory", str(directory))
    monkeypatch.setattr("entrascope.cli.choose", lambda *a, **k: None)
    monkeypatch.setattr("entrascope.cli.available", lambda: False)
    result = run("config", "credentials", "--choose", input="2\n")
    assert result.exit_code == 0
    assert load_config().credentials.file.filename == "staging.json"


def test_the_chooser_answer_is_taken_when_there_is_a_terminal(
    own_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One keystroke, and the next run does not ask."""
    directory = credential_directory(tmp_path, "prod.json", "staging.json")
    run("config", "credentials", "--directory", str(directory))
    monkeypatch.setattr("entrascope.cli.choose", lambda *a, **k: "prod.json")
    result = run("config", "credentials", "--choose")
    assert result.exit_code == 0
    assert load_config().credentials.file.filename == "prod.json"


def test_declining_the_chooser_changes_nothing(
    own_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deciding against it is an answer, and it is not this one."""
    directory = credential_directory(tmp_path, "prod.json")
    run("config", "credentials", "--directory", str(directory))
    before = load_config().credentials.file.filename
    monkeypatch.setattr("entrascope.cli.choose", lambda *a, **k: None)
    monkeypatch.setattr("entrascope.cli.available", lambda: True)
    run("config", "credentials", "--choose")
    assert load_config().credentials.file.filename == before


def test_a_file_with_comments_is_copied_aside_before_it_is_rewritten(
    own_config: Path, tmp_path: Path
) -> None:
    """Losing somebody's notes without saying so is worse than the extra file."""
    own_config.mkdir(parents=True)
    path = own_config / CREDENTIALS_FILE
    path.write_text("# mine\nfile:\n  filename: kept.json\n", encoding="utf-8")
    written, backup = write_user_config(CREDENTIALS_FILE, {"file": {"directory": "/x"}})
    assert written == path
    assert backup is not None
    assert "# mine" in backup.read_text()
    # The value that was there is still there.
    assert load_config().credentials.file.filename == "kept.json"


def test_a_file_without_comments_needs_no_copy(own_config: Path) -> None:
    """A backup for every write would litter the directory for no reason."""
    own_config.mkdir(parents=True)
    (own_config / CREDENTIALS_FILE).write_text(
        "file:\n  filename: a.json\n", encoding="utf-8"
    )
    _, backup = write_user_config(CREDENTIALS_FILE, {"file": {"filename": "b.json"}})
    assert backup is None


def test_the_banner_names_the_kind_and_the_file(config: Config) -> None:
    """The two questions worth answering before an answer arrives."""
    line = credential_banner(
        CredentialPosture(
            source="file",
            kind="certificate",
            file_path="/home/ada/.entra/prod.json",
            file_present=True,
            certificate_path="/home/ada/.entra/app.pem",
        ),
        config,
    )
    assert config.credentials.kinds["certificate"] in line
    assert "/home/ada/.entra/prod.json" in line
    assert "/home/ada/.entra/app.pem" in line
    assert "\n" not in line


def test_the_banner_says_when_a_file_is_not_there(config: Config) -> None:
    """Because that is the commonest reason a run authenticates as something else."""
    line = credential_banner(
        CredentialPosture(
            source="azure-cli",
            kind="session",
            file_path="/home/ada/.entra/prod.json",
            file_present=False,
        ),
        config,
    )
    assert "not there" in line
    assert config.credentials.kinds["session"] in line


def test_the_banner_is_one_line_whatever_it_is_given(config: Config) -> None:
    """A display name can forge a log line, and a path could forge a banner."""
    line = credential_banner(
        CredentialPosture(
            source="file",
            kind="secret",
            file_path="/x",
            file_present=True,
            problem="unsafe\ncredentials: pretending to be another line",
        ),
        config,
    )
    assert "\n" not in line


def test_the_banner_is_only_for_output_somebody_reads(
    own_config: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A banner in front of JSON is a banner in somebody's parser."""
    monkeypatch.setattr("sys.stderr.isatty", lambda: True, raising=False)
    from entrascope.cli import announce_credentials

    active = load_config()
    announce_credentials(active, "json", None, None)
    assert capsys.readouterr().err == ""
    announce_credentials(active, "table", None, None)
    assert active.credentials.banner.prefix in capsys.readouterr().err


def test_the_banner_can_be_switched_off(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Configuration, like everything else about it."""
    monkeypatch.setattr("sys.stderr.isatty", lambda: True, raising=False)
    from entrascope.cli import announce_credentials

    active = load_config()
    quiet = active.model_copy(
        update={
            "credentials": active.credentials.model_copy(
                update={
                    "banner": active.credentials.banner.model_copy(
                        update={"enabled": False}
                    )
                }
            )
        }
    )
    announce_credentials(quiet, "table", None, None)
    assert capsys.readouterr().err == ""


def test_the_banner_never_stops_a_command(
    monkeypatch: pytest.MonkeyPatch, config: Config
) -> None:
    """What it reports is worth nothing beside the command somebody asked for."""
    monkeypatch.setattr("sys.stderr.isatty", lambda: True, raising=False)
    monkeypatch.setattr(
        "entrascope.cli.posture",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no")),
    )
    from entrascope.cli import announce_credentials

    announce_credentials(config, "table", None, None)


def offering(**settings: Any) -> bool:
    """Ask whether a file would be offered, with the given settings."""
    return worth_offering_a_file(settings, settings.pop("current"))


def test_a_file_is_not_offered_when_one_was_named(
    config: Config, tmp_path: Path
) -> None:
    """Asking again would be asking somebody to repeat themselves."""
    current = posture(config, home=tmp_path)
    assert not offering(
        config=config, credential_file="named.json", auth=None, current=current
    )


def test_a_file_is_not_offered_for_another_source(
    config: Config, tmp_path: Path
) -> None:
    """Somebody who asked for the Azure CLI session did not ask about files."""
    current = posture(config, home=tmp_path)
    assert not offering(
        config=config, credential_file=None, auth="azure-cli", current=current
    )


def test_a_file_is_not_offered_without_a_terminal(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unattended run must fail the way it always did, not wait for nobody."""
    directory = tmp_path / ".entra"
    directory.mkdir(parents=True, mode=0o700)
    (directory / "staging.json").write_text("{}")
    current = posture(config, home=tmp_path)._replace(
        file_present=False, alternatives=("staging.json",)
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    assert not offering(config=config, credential_file=None, auth=None, current=current)


def test_a_file_is_offered_when_there_is_one_and_somebody_to_ask(
    config: Config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole point: the answer is sitting in the directory already."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True, raising=False)
    current = CredentialPosture(
        source=None,
        kind="none",
        file_path="/home/ada/.entra/provisioner-credentials.json",
        file_present=False,
        alternatives=("staging.json",),
    )
    assert offering(config=config, credential_file=None, auth=None, current=current)


def test_a_file_is_not_offered_when_the_one_there_is_unsafe(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """That refusal is the answer, and offering another would work around it."""
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True, raising=False)
    current = CredentialPosture(
        source=None,
        kind="none",
        file_path="/x",
        file_present=True,
        problem="readable by others",
        alternatives=("staging.json",),
    )
    assert not offering(config=config, credential_file=None, auth=None, current=current)


def test_the_missing_file_is_settled_before_authenticating(
    own_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole flow, from a run that would have failed to one that does not.

    A command asks for an identity, the configured file is not there, the
    files that are there are offered, and the answer is both used for this run
    and remembered for the next one.
    """
    from entrascope.cli import settle_the_credential_file

    directory = credential_directory(tmp_path, "prod.json", "staging.json")
    run("config", "credentials", "--directory", str(directory))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True, raising=False)
    monkeypatch.setattr("entrascope.cli.choose", lambda *a, **k: "staging.json")

    settings: dict[str, Any] = {
        "config": load_config(),
        "config_dir": None,
        "auth": None,
        "credential_file": None,
    }
    settle_the_credential_file(settings)
    assert settings["credential_file"] == "staging.json"
    assert load_config().credentials.file.filename == "staging.json"


def test_nothing_is_settled_when_the_file_is_there(
    own_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Offering a choice nobody needs to make is worse than not offering one."""
    from entrascope.cli import settle_the_credential_file

    directory = credential_directory(tmp_path, "prod.json")
    run("config", "credentials", "--directory", str(directory), "--file", "prod.json")
    asked = []
    monkeypatch.setattr(
        "entrascope.cli.choose", lambda *a, **k: asked.append(True) or "prod.json"
    )
    settings: dict[str, Any] = {
        "config": load_config(),
        "config_dir": None,
        "auth": None,
        "credential_file": None,
    }
    settle_the_credential_file(settings)
    assert not asked
    assert settings["credential_file"] is None


def test_declining_leaves_the_run_to_fail_as_it_always_did(
    own_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Choosing nothing is an answer. It is not an instruction to guess."""
    from entrascope.cli import settle_the_credential_file

    directory = credential_directory(tmp_path, "prod.json")
    run("config", "credentials", "--directory", str(directory))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True, raising=False)
    monkeypatch.setattr("entrascope.cli.choose", lambda *a, **k: None)
    monkeypatch.setattr("entrascope.cli.available", lambda: True)
    settings: dict[str, Any] = {
        "config": load_config(),
        "config_dir": None,
        "auth": None,
        "credential_file": None,
    }
    settle_the_credential_file(settings)
    assert settings["credential_file"] is None


def test_a_named_environment_file_is_not_second_guessed(
    own_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Setting the variable is an answer, and asking again ignores it."""
    directory = credential_directory(tmp_path, "prod.json")
    run("config", "credentials", "--directory", str(directory))
    active = load_config()
    monkeypatch.setenv(
        active.credentials.file.environment_variable, str(directory / "prod.json")
    )
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)
    monkeypatch.setattr("sys.stderr.isatty", lambda: True, raising=False)
    current = posture(active)
    assert not offering(config=active, credential_file=None, auth=None, current=current)


def test_a_file_name_cannot_forge_a_line_of_the_list(
    own_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file name is text this tool did not write.

    Anybody who can create a file in the credential directory chooses it, and
    a newline in one would forge a line of the list somebody is picking from.
    The name used to open the file is still the real one; only what is shown
    is reduced to a line.
    """
    directory = credential_directory(tmp_path)
    forging = directory / "a\nb  2  looks-like-another-choice.json"
    forging.write_text(
        json.dumps({"ClientID": "a", "TenantID": "b", "Secret": "c"}), encoding="utf-8"
    )
    forging.chmod(0o600)
    run("config", "credentials", "--directory", str(directory))
    monkeypatch.setattr("entrascope.cli.choose", lambda *a, **k: None)
    monkeypatch.setattr("entrascope.cli.available", lambda: False)
    result = run("config", "credentials", "--choose", input="\n")
    shown = [line for line in result.output.splitlines() if "looks-like" in line]
    assert shown, "the file should still be offered"
    assert len(shown) == 1
    assert shown[0].startswith("  1  ")
