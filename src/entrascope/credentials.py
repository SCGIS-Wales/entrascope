"""Credentials, file permissions and the four authentication sources.

The credential contract is fixed and is documented in
docs/steering/credentials-and-security.md. The secret is never logged and never
printed, and this module refuses to run at all when the credential file is
readable by anyone other than its owner.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from collections.abc import Mapping
from pathlib import Path

from azure.core.credentials import TokenCredential
from azure.identity import (
    AzureCliCredential,
    ClientSecretCredential,
    DefaultAzureCredential,
)

from entrascope.config import Config, Credentials
from entrascope.http import verify_setting
from entrascope.logger import bind_context, get_logger
from entrascope.models import (
    AUTH_SOURCE_ORDER,
    AuthContext,
    AuthSource,
    AuthSourceUnavailableError,
    CheckResult,
    Credential,
    CredentialError,
    IdentityKind,
)

log = get_logger(__name__)

#: Name of the Azure CLI executable, looked up on PATH.
AZURE_CLI_EXECUTABLE = "az"


def unsafe_reason(
    settings: Credentials, home: Path | None = None, named: str | None = None
) -> str:
    """Return why an existing credential file cannot be used, or nothing.

    A file that is not there is not a problem: something else will answer. A
    file that is there and is readable by anyone else is a problem, and the
    contract says so plainly. The two must not be treated alike.
    """
    if not resolve_file(settings, home, named).is_file():
        return ""
    for result in check_permissions(settings, home, named):
        if not result.passed:
            return f"{result.detail} Fix it with: {result.remediation}"
    return ""


def first_line(error: Exception) -> str:
    """Return the first line of an error, which is the part that says what."""
    return str(error).splitlines()[0] if str(error) else error.__class__.__name__


def resolve_directory(settings: Credentials, home: Path | None = None) -> Path:
    """Return the directory that holds the credential file."""
    raw = settings.file.directory
    if raw.startswith("~"):
        base = home if home is not None else Path.home()
        return base / raw.removeprefix("~").lstrip("/")
    return Path(raw)


def resolve_file(
    settings: Credentials,
    home: Path | None = None,
    named: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Return the credential file to read.

    A name given on the command line wins, then the environment variable, then
    the configured file name. A name with no path in it is taken as a file
    inside the credential directory, which is what somebody means when they say
    they have another one next to the first.
    """
    source = os.environ if environ is None else environ
    chosen = named or source.get(settings.file.environment_variable, "").strip()
    if not chosen:
        return resolve_directory(settings, home) / settings.file.filename
    if chosen.startswith("~"):
        base = home if home is not None else Path.home()
        return base / chosen.removeprefix("~").lstrip("/")
    candidate = Path(chosen)
    if candidate.is_absolute() or len(candidate.parts) > 1:
        return candidate
    return resolve_directory(settings, home) / chosen


def other_files(settings: Credentials, home: Path | None = None) -> tuple[str, ...]:
    """Return the other credential files sitting in the directory.

    Somebody who keeps one file per tenant has the answer in front of them, and
    naming it is more use than repeating what was expected.
    """
    directory = resolve_directory(settings, home)
    if not directory.is_dir():
        return ()
    return tuple(
        sorted(
            item.name
            for item in directory.iterdir()
            if item.is_file() and item.suffix == ".json"
        )
    )


def permission_bits(path: Path) -> int:
    """Return the permission bits of a path, masked to the meaningful nine."""
    return stat.S_IMODE(path.stat().st_mode)


def required_mode(value: str) -> int:
    """Parse a mode written in configuration as an octal string."""
    return int(value, 8)


def format_mode(bits: int) -> str:
    """Render permission bits the way chmod reports them."""
    return format(bits, "04o")


def check_directory_mode(
    settings: Credentials, home: Path | None = None
) -> CheckResult:
    """Check that the credential directory is accessible only to its owner."""
    directory = resolve_directory(settings, home)
    wanted = required_mode(settings.file.required_directory_mode)
    if not directory.is_dir():
        return CheckResult(
            check="credential directory",
            passed=False,
            detail=f"{directory} does not exist.",
            remediation=(
                f"mkdir -p {directory} && chmod {format_mode(wanted)} {directory}"
            ),
        )
    actual = permission_bits(directory)
    if actual != wanted:
        return CheckResult(
            check="credential directory",
            passed=False,
            detail=(
                f"{directory} has mode {format_mode(actual)} and must have "
                f"{format_mode(wanted)}."
            ),
            remediation=f"chmod {format_mode(wanted)} {directory}",
        )
    return CheckResult(
        check="credential directory",
        passed=True,
        detail=f"{directory} has mode {format_mode(actual)}.",
    )


def check_file_mode(
    settings: Credentials, home: Path | None = None, named: str | None = None
) -> CheckResult:
    """Check that the credential file is readable only by its owner."""
    path = resolve_file(settings, home, named)
    wanted = required_mode(settings.file.required_file_mode)
    if not path.is_file():
        alternatives = tuple(
            name for name in other_files(settings, home) if name != path.name
        )
        nearby = (
            f"\nThese are in {resolve_directory(settings, home)}: "
            f"{', '.join(alternatives)}. Use one with "
            f"--credentials {alternatives[0]}"
            if alternatives
            else ""
        )
        return CheckResult(
            check="credential file",
            passed=False,
            detail=f"{path} does not exist.{nearby}",
            remediation=(
                f"Create {path} with the keys "
                f"{sorted(settings.file.keys.values())} and run "
                f"chmod {format_mode(wanted)} {path}"
                if not alternatives
                else f"Pass --credentials {alternatives[0]}, or set "
                f"{settings.file.environment_variable}, or create {path}."
            ),
        )
    actual = permission_bits(path)
    if actual != wanted:
        return CheckResult(
            check="credential file",
            passed=False,
            detail=(
                f"{path} has mode {format_mode(actual)} and must have "
                f"{format_mode(wanted)}. It is readable by others."
            ),
            remediation=f"chmod {format_mode(wanted)} {path}",
        )
    return CheckResult(
        check="credential file",
        passed=True,
        detail=f"{path} has mode {format_mode(actual)}.",
    )


def check_permissions(
    settings: Credentials, home: Path | None = None, named: str | None = None
) -> tuple[CheckResult, ...]:
    """Check the credential directory and the credential file together."""
    return (
        check_directory_mode(settings, home),
        check_file_mode(settings, home, named),
    )


def read_checked(path: Path, settings: Credentials) -> str:
    """Read the credential file, checking the file that was actually opened.

    Checking the path and then opening it leaves a gap in which the path can be
    replaced. The mode is taken from the open descriptor, so what was checked
    and what was read are the same file.
    """
    wanted = required_mode(settings.file.required_file_mode)
    with path.open("rb") as handle:
        actual = stat.S_IMODE(os.fstat(handle.fileno()).st_mode)
        if actual != wanted:
            raise CredentialError(
                f"{path} has mode {format_mode(actual)} and must have "
                f"{format_mode(wanted)}. It is readable by others. "
                f"Fix it with: chmod {format_mode(wanted)} {path}"
            )
        return handle.read().decode("utf-8")


def read_credential_file(
    settings: Credentials, home: Path | None = None, named: str | None = None
) -> Credential:
    """Read and validate the credential file.

    Refuses to run when the file or its directory is group or world accessible.
    The remediation names the exact chmod and never reveals the secret.
    """
    for result in check_permissions(settings, home, named):
        if not result.passed:
            raise CredentialError(f"{result.detail} Fix it with: {result.remediation}")

    path = resolve_file(settings, home, named)
    try:
        payload = json.loads(read_checked(path, settings))
    except (OSError, json.JSONDecodeError) as error:
        raise CredentialError(f"Cannot read {path}: {error}") from error
    if not isinstance(payload, Mapping):
        raise CredentialError(f"{path} must contain a JSON object.")

    keys = settings.file.keys
    missing = [name for name in keys.values() if not payload.get(name)]
    if missing:
        raise CredentialError(
            f"{path} is missing the keys {sorted(missing)}. "
            f"The required keys are {sorted(keys.values())}."
        )
    return Credential(
        client_id=str(payload[keys["client_id"]]),
        tenant_id=str(payload[keys["tenant_id"]]),
        secret=str(payload[keys["secret"]]),
    )


def read_environment(
    settings: Credentials, environ: Mapping[str, str] | None = None
) -> Credential | None:
    """Return client credentials from the environment, or None if incomplete."""
    source = os.environ if environ is None else environ
    names = settings.environment
    client_id = source.get(names.client_id, "")
    secret = source.get(names.secret, "")
    tenant_id = source.get(names.tenant_id, "")
    if not (client_id and secret and tenant_id):
        return None
    return Credential(client_id=client_id, tenant_id=tenant_id, secret=secret)


def azure_cli_available(which: object = None) -> bool:
    """Return whether the Azure CLI is on PATH."""
    finder = shutil.which if which is None else which
    assert callable(finder)
    return bool(finder(AZURE_CLI_EXECUTABLE))


def identity_kind(settings: Credentials, source: AuthSource) -> IdentityKind:
    """Return whether a source yields application or delegated access."""
    value = settings.sources.identity_kind.get(source, "unknown")
    if value == "application":
        return "application"
    if value == "delegated":
        return "delegated"
    return "unknown"


def source_enabled(settings: Credentials, source: AuthSource) -> bool:
    """Return whether a source may be tried during automatic resolution."""
    return bool(settings.sources.enabled.get(source, False))


def resolution_order(settings: Credentials) -> tuple[AuthSource, ...]:
    """Return the configured resolution order, validated against the known sources."""
    configured = [
        source for source in AUTH_SOURCE_ORDER if source in settings.sources.order
    ]
    missing = [source for source in AUTH_SOURCE_ORDER if source not in configured]
    ordering = {name: index for index, name in enumerate(settings.sources.order)}
    configured.sort(key=lambda source: ordering[source])
    return (*configured, *missing)


def build_client_secret_credential(
    credential: Credential, verify: str | bool = True
) -> TokenCredential:
    """Build a client credentials token source.

    The verification setting is passed through so that the token endpoint is
    reached through the same proxy and trusted against the same certificate
    authority as every other call.
    """
    # framework contract: azure-identity requires a credential object. It is
    # treated as configuration and carries none of our logic.
    return ClientSecretCredential(
        tenant_id=credential.tenant_id,
        client_id=credential.client_id,
        client_secret=credential.secret,
        connection_verify=verify,
    )


def build_azure_cli_credential() -> TokenCredential:
    """Build a token source backed by the Azure CLI session.

    The Azure CLI holds its own session and its own proxy and certificate
    configuration, so nothing is passed through here.
    """
    # framework contract: azure-identity requires a credential object.
    return AzureCliCredential()


def build_default_credential(verify: str | bool = True) -> TokenCredential:
    """Build the full azure-identity chained token source."""
    # framework contract: azure-identity requires a credential object.
    return DefaultAzureCredential(connection_verify=verify)


def describe(source: AuthSource, credential: Credential | None) -> str:
    """Return a one line description of an authenticated identity."""
    if source == "file":
        return "client credentials from the credential file"
    if source == "env":
        return "client credentials from the environment"
    if source == "azure-cli":
        return "the signed in Azure CLI session"
    _ = credential
    return "the default azure-identity chain"


def try_source(
    source: AuthSource,
    config: Config,
    home: Path | None = None,
    environ: Mapping[str, str] | None = None,
    named: str | None = None,
) -> tuple[AuthContext, TokenCredential]:
    """Build a token source for one authentication source, or fail loudly."""
    settings = config.credentials
    if source == "file":
        credential = read_credential_file(settings, home, named)
        context = AuthContext(
            source=source,
            identity_kind=identity_kind(settings, source),
            tenant_id=credential.tenant_id,
            client_id=credential.client_id,
            description=(
                "client credentials from "
                f"{resolve_file(settings, home, named, environ)}"
            ),
        )
        return context, build_client_secret_credential(
            credential, verify_setting(config, environ)
        )

    if source == "env":
        from_environment = read_environment(settings, environ)
        if from_environment is None:
            names = settings.environment
            raise AuthSourceUnavailableError(
                "The environment does not carry client credentials. Set "
                f"{names.client_id}, {names.secret} and {names.tenant_id}."
            )
        context = AuthContext(
            source=source,
            identity_kind=identity_kind(settings, source),
            tenant_id=from_environment.tenant_id,
            client_id=from_environment.client_id,
            description=describe(source, from_environment),
        )
        return context, build_client_secret_credential(
            from_environment, verify_setting(config, environ)
        )

    if source == "azure-cli":
        if not azure_cli_available():
            raise AuthSourceUnavailableError(
                "The Azure CLI is not on PATH. Install it and run az login, or "
                "choose another source with --auth."
            )
        context = AuthContext(
            source=source,
            identity_kind=identity_kind(settings, source),
            tenant_id=None,
            client_id=None,
            description=describe(source, None),
        )
        return context, build_azure_cli_credential()

    context = AuthContext(
        source="default",
        identity_kind=identity_kind(settings, "default"),
        tenant_id=None,
        client_id=None,
        description=describe("default", None),
    )
    return context, build_default_credential(verify_setting(config, environ))


def resolve_auth(
    config: Config,
    requested: AuthSource | None = None,
    home: Path | None = None,
    environ: Mapping[str, str] | None = None,
    named: str | None = None,
) -> tuple[AuthContext, TokenCredential]:
    """Return the identity to authenticate as, and the token source for it.

    Naming a source explicitly selects it whether or not it is enabled for
    automatic resolution, so an engineer who has run az login can pass
    --auth azure-cli with no configuration change. Naming a credential file
    means the file source, because there is nothing else it could mean.
    Without an explicit choice the enabled sources are tried in the configured
    order and the first that works wins.
    """
    settings = config.credentials
    if named and requested is None:
        requested = "file"
    if requested is not None:
        context, credential = try_source(requested, config, home, environ, named)
        bind_context(auth_source=context.source, tenant_id=context.tenant_id or "")
        log.debug("authenticated using %s", context.description)
        return context, credential

    # A credential file that is there but unsafe stops everything. Working
    # around it would leave a secret readable by others while the tool carried
    # on as though nothing were wrong, and the contract says refuse to run.
    unsafe = unsafe_reason(settings, home, named)
    if unsafe:
        raise CredentialError(
            f"The credential file cannot be used, and entrascope will not work "
            f"around it.\n  {unsafe}\n"
            "  Fix that, or name another source with --auth to leave the file "
            "alone."
        )

    failures: list[str] = []
    for source in resolution_order(settings):
        if not source_enabled(settings, source):
            failures.append(f"{source}: not enabled for automatic resolution")
            continue
        try:
            context, credential = try_source(source, config, home, environ, named)
        except (CredentialError, AuthSourceUnavailableError) as error:
            failures.append(f"{source}: {first_line(error)}")
            continue
        bind_context(auth_source=context.source, tenant_id=context.tenant_id or "")
        log.debug("authenticated using %s", context.description)
        # What was passed over on the way is worth saying. A source that was
        # expected to answer and quietly did not is the commonest confusion
        # there is, and nothing else reports it. It goes to debug because the
        # case that actually matters, an unusable credential file, is now an
        # error rather than something to be read about afterwards.
        for skipped in failures:
            log.debug("passed over %s", skipped)
        return context._replace(skipped=tuple(failures)), credential

    tried = ", ".join(
        source
        for source in resolution_order(settings)
        if source_enabled(settings, source)
    )
    detail = "\n  ".join(failures) if failures else "no source is enabled."
    raise CredentialError(
        f"No authentication source succeeded. Tried: {tried}.\n  "
        f"{detail}\n"
        "Run az login, or place client credentials in the credential file, or "
        "name a source explicitly with --auth."
    )
