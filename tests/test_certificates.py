"""A certificate in place of a secret, and the posture that reports which.

Entra accepts either for an application. The certificate is the better of the
two and was the half this tool could not use, so these cover both the reading
of one and the refusal to use one anybody else can read.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from entrascope.config import Config
from entrascope.credentials import (
    build_application_credential,
    check_certificate_mode,
    check_permissions,
    file_kind,
    kind_label,
    other_files,
    posture,
    read_credential_file,
    read_environment,
    resolve_certificate,
)
from entrascope.models import Credential, CredentialError
from tests.conftest import SENTINEL_SECRET

#: Enough of a PEM to be a file. Nothing here parses one: azure-identity does
#: that, and it is not what these tests are about.
PEM = "-----BEGIN PRIVATE KEY-----\nnot a real key\n-----END PRIVATE KEY-----\n"


def write_certificate(
    directory: Path, name: str = "app.pem", mode: int = 0o600
) -> Path:
    """Put a certificate file in place with the mode a test wants."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(PEM, encoding="utf-8")
    path.chmod(mode)
    return path


def write_file(
    home: Path,
    config: Config,
    payload: dict[str, object],
    *,
    mode: int = 0o600,
) -> Path:
    """Write a credential file under a temporary home directory."""
    directory = home / ".entra"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / config.credentials.file.filename
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(mode)
    directory.chmod(0o700)
    return path


def identifying(config: Config) -> dict[str, object]:
    """Return the two keys every credential file needs whichever kind it is."""
    keys = config.credentials.file.keys
    return {
        keys["client_id"]: "11111111-1111-1111-1111-111111111111",
        keys["tenant_id"]: "22222222-2222-2222-2222-222222222222",
    }


def test_a_file_naming_a_certificate_authenticates_with_it(
    tmp_path: Path, config: Config
) -> None:
    """The half of the contract that could not be used before this."""
    certificate = write_certificate(tmp_path / ".entra")
    write_file(
        tmp_path,
        config,
        identifying(config) | {config.credentials.certificate.keys["path"]: "app.pem"},
    )
    credential = read_credential_file(config.credentials, tmp_path)
    assert credential.kind() == "certificate"
    assert credential.certificate_path == str(certificate)
    assert credential.secret == ""


def test_a_relative_certificate_is_beside_the_credential_file(
    tmp_path: Path, config: Config
) -> None:
    """Which is where somebody keeps a key that belongs to one file."""
    write_certificate(tmp_path / ".entra", "beside.pem")
    resolved = resolve_certificate(config.credentials, "beside.pem", tmp_path)
    assert resolved == tmp_path / ".entra" / "beside.pem"


def test_an_absolute_certificate_is_used_as_it_stands(
    tmp_path: Path, config: Config
) -> None:
    """A path somebody wrote out in full is an answer, not a suggestion."""
    elsewhere = write_certificate(tmp_path / "keys")
    assert (
        resolve_certificate(config.credentials, str(elsewhere), tmp_path) == elsewhere
    )


def test_a_certificate_readable_by_others_is_refused(
    tmp_path: Path, config: Config
) -> None:
    """The private key in it is exactly as sensitive as a secret.

    A key the group can read is a key the group can authenticate with, so this
    refuses for the same reason the credential file itself does.
    """
    write_certificate(tmp_path / ".entra", mode=0o644)
    write_file(
        tmp_path,
        config,
        identifying(config) | {config.credentials.certificate.keys["path"]: "app.pem"},
    )
    with pytest.raises(CredentialError, match="chmod 0600"):
        read_credential_file(config.credentials, tmp_path)


def test_a_certificate_that_is_not_there_is_reported(
    tmp_path: Path, config: Config
) -> None:
    """Naming a key that is missing is a different mistake from naming none."""
    result = check_certificate_mode(config.credentials, tmp_path / "gone.pem")
    assert not result.passed
    assert "does not exist" in result.detail


def test_a_file_carrying_both_prefers_the_certificate(
    tmp_path: Path, config: Config
) -> None:
    """It is the stronger of the two, and having put one there means it."""
    write_certificate(tmp_path / ".entra")
    write_file(
        tmp_path,
        config,
        identifying(config)
        | {
            config.credentials.file.keys["secret"]: SENTINEL_SECRET,
            config.credentials.certificate.keys["path"]: "app.pem",
        },
    )
    assert read_credential_file(config.credentials, tmp_path).kind() == "certificate"


def test_a_file_carrying_neither_is_refused(tmp_path: Path, config: Config) -> None:
    """There is nothing to authenticate with, and saying so beats a 401."""
    write_file(tmp_path, config, identifying(config))
    with pytest.raises(CredentialError, match="neither"):
        read_credential_file(config.credentials, tmp_path)
    assert "Secret" in str(config.credentials.file.keys.values())


def test_a_file_missing_its_identifiers_names_them(
    tmp_path: Path, config: Config
) -> None:
    """Client id and tenant id are needed whichever kind of credential it is."""
    write_file(
        tmp_path, config, {config.credentials.file.keys["secret"]: SENTINEL_SECRET}
    )
    with pytest.raises(CredentialError, match="missing the keys"):
        read_credential_file(config.credentials, tmp_path)


def test_the_configured_default_certificate_fills_in(
    tmp_path: Path, config: Config
) -> None:
    """So a machine set up for certificates needs no change to every file."""
    certificate = write_certificate(tmp_path / "keys")
    settings = config.credentials.model_copy(
        update={
            "certificate": config.credentials.certificate.model_copy(
                update={"default_path": str(certificate)}
            )
        }
    )
    write_file(tmp_path, config, identifying(config))
    credential = read_credential_file(settings, tmp_path)
    assert credential.kind() == "certificate"
    assert credential.certificate_path == str(certificate)


def test_the_environment_can_carry_a_certificate(
    tmp_path: Path, config: Config
) -> None:
    """Under the names the Azure provider for Terraform already uses."""
    certificate = write_certificate(tmp_path / "keys")
    names = config.credentials.environment
    credential = read_environment(
        config.credentials,
        {
            names.client_id: "11111111-1111-1111-1111-111111111111",
            names.tenant_id: "22222222-2222-2222-2222-222222222222",
            names.certificate_path: str(certificate),
        },
        tmp_path,
    )
    assert credential is not None
    assert credential.kind() == "certificate"


def test_the_environment_without_either_carries_nothing(config: Config) -> None:
    """A client id on its own is not a credential."""
    names = config.credentials.environment
    assert read_environment(config.credentials, {names.client_id: "a"}) is None


def test_the_permission_checks_include_a_named_certificate(
    tmp_path: Path, config: Config
) -> None:
    """A file that names a key is only as safe as the key it names."""
    write_certificate(tmp_path / ".entra", mode=0o644)
    write_file(
        tmp_path,
        config,
        identifying(config) | {config.credentials.certificate.keys["path"]: "app.pem"},
    )
    results = check_permissions(config.credentials, tmp_path)
    assert [result.check for result in results] == [
        "credential directory",
        "credential file",
        "certificate",
    ]
    assert not results[-1].passed


def test_an_unsafe_credential_file_is_never_parsed(
    tmp_path: Path, config: Config
) -> None:
    """Reading a file just refused would be the tool ignoring its own answer."""
    write_certificate(tmp_path / ".entra")
    write_file(
        tmp_path,
        config,
        identifying(config) | {config.credentials.certificate.keys["path"]: "app.pem"},
        mode=0o644,
    )
    results = check_permissions(config.credentials, tmp_path)
    assert [result.check for result in results] == [
        "credential directory",
        "credential file",
    ]


def test_a_certificate_password_never_reaches_a_representation() -> None:
    """repr is where a secret leaks into a traceback nobody meant to keep."""
    shown = repr(
        Credential(
            client_id="a",
            tenant_id="b",
            secret=SENTINEL_SECRET,
            certificate_path="/keys/app.pem",
            certificate_password="the-passphrase",
        )
    )
    assert SENTINEL_SECRET not in shown
    assert "the-passphrase" not in shown
    # The path is worth seeing. What it protects is the key inside the file.
    assert "/keys/app.pem" in shown


def test_a_credential_with_neither_reports_no_kind() -> None:
    """Which is what the banner shows rather than guessing at a secret."""
    assert Credential(client_id="a", tenant_id="b").kind() == "none"


@lru_cache(maxsize=1)
def real_pem() -> str:
    """Return a self signed certificate and its key, generated once.

    azure-identity parses the file as it is handed one, so the builder cannot
    be tested with a placeholder. Nothing here is ever sent anywhere: the key
    exists for the length of one test process.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "entrascope tests")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return (
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        + certificate.public_bytes(serialization.Encoding.PEM)
    ).decode("ascii")


def test_the_builder_chooses_by_kind(tmp_path: Path) -> None:
    """One function, so no caller has to remember to look for a certificate."""
    certificate = tmp_path / "real.pem"
    certificate.write_text(real_pem(), encoding="ascii")
    certificate.chmod(0o600)
    built = build_application_credential(
        Credential(
            client_id="11111111-1111-1111-1111-111111111111",
            tenant_id="22222222-2222-2222-2222-222222222222",
            certificate_path=str(certificate),
        )
    )
    assert type(built).__name__ == "CertificateCredential"
    secret_built = build_application_credential(
        Credential(client_id="a", tenant_id="b", secret=SENTINEL_SECRET)
    )
    assert type(secret_built).__name__ == "ClientSecretCredential"


def test_the_discovery_glob_decides_what_is_offered(
    tmp_path: Path, config: Config
) -> None:
    """A shop naming them .cred should not have to rename them to be offered."""
    directory = tmp_path / ".entra"
    directory.mkdir(parents=True)
    (directory / "one.json").write_text("{}")
    (directory / "two.cred").write_text("{}")
    assert other_files(config.credentials, tmp_path) == ("one.json",)
    widened = config.credentials.model_copy(
        update={
            "file": config.credentials.file.model_copy(
                update={"discovery_glob": "*.cred"}
            )
        }
    )
    assert other_files(widened, tmp_path) == ("two.cred",)


def test_a_file_that_cannot_be_read_reports_no_kind(
    tmp_path: Path, config: Config
) -> None:
    """Saying which kind is in a file is no reason at all to stop a run."""
    write_file(tmp_path, config, identifying(config))
    assert file_kind(config.credentials, tmp_path) == "none"


def test_the_kind_labels_come_from_configuration(config: Config) -> None:
    """Because how a thing is named in output is not a decision code makes."""
    assert (
        kind_label(config.credentials, "certificate")
        == (config.credentials.kinds["certificate"])
    )
    assert kind_label(config.credentials, "unheard-of") == "unheard-of"


def test_the_posture_names_the_file_and_the_kind(
    tmp_path: Path, config: Config
) -> None:
    """What a run would authenticate as, worked out without authenticating."""
    path = write_file(
        tmp_path,
        config,
        identifying(config) | {config.credentials.file.keys["secret"]: SENTINEL_SECRET},
    )
    current = posture(config, home=tmp_path)
    assert current.source == "file"
    assert current.kind == "secret"
    assert current.file_present
    assert current.file_path == str(path)
    assert current.problem == ""


def test_the_posture_reports_a_file_anybody_can_read(
    tmp_path: Path, config: Config
) -> None:
    """An unsafe file is passed over, and why is the point of showing it."""
    write_file(
        tmp_path,
        config,
        identifying(config) | {config.credentials.file.keys["secret"]: SENTINEL_SECRET},
        mode=0o644,
    )
    current = posture(config, home=tmp_path)
    assert current.source != "file"
    assert "chmod 0600" in current.problem


def test_the_posture_lists_the_files_beside_a_missing_one(
    tmp_path: Path, config: Config
) -> None:
    """Which is what makes offering them possible."""
    directory = tmp_path / ".entra"
    directory.mkdir(parents=True, mode=0o700)
    (directory / "staging.json").write_text("{}")
    current = posture(config, home=tmp_path)
    assert not current.file_present
    assert current.alternatives == ("staging.json",)


def test_a_named_source_is_reported_as_asked_for(
    tmp_path: Path, config: Config
) -> None:
    """Naming a source with --auth means that source, enabled or not."""
    current = posture(config, "default", home=tmp_path)
    assert current.source == "default"
    assert current.kind == "chain"


def test_the_posture_never_authenticates(tmp_path: Path, config: Config) -> None:
    """No token request, so it costs nothing before every command.

    Proved by giving it a home with nothing in it and no network at all: a
    posture still comes back rather than a connection error.
    """
    current = posture(config, home=tmp_path)
    assert current.kind in config.credentials.kinds
