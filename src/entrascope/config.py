"""Configuration loading.

This is the only module that opens a YAML file. Every other module receives
configuration as an argument or asks :func:`load_config` for it, and that
function caches its result.

Each file is validated against a schema at load time, so a malformed file fails
immediately with a readable message rather than at the point of use.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

from entrascope.models import ConfigError

#: Environment variable that overrides where configuration is read from.
CONFIG_DIR_VARIABLE = "ENTRASCOPE_CONFIG_DIR"

#: Directory of packaged configuration inside an installed wheel.
PACKAGED_CONFIG_DIRNAME = "_config"

#: File that marks a directory as a configuration directory.
SENTINEL_FILE = "endpoints.yaml"


# framework contract: pydantic requires model classes for schema validation.
# These carry no behaviour. All logic lives in the free functions below.
class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow")


class AuthorityVersion2(_Frozen):
    issuer_template: str
    token_endpoint_template: str
    authorize_endpoint_template: str
    jwks_uri_template: str
    oidc_discovery_template: str


class AuthorityVersion1(_Frozen):
    issuer_template: str
    token_endpoint_template: str


class Authority(_Frozen):
    base_url: str
    v2: AuthorityVersion2
    v1: AuthorityVersion1


class GraphEndpoints(_Frozen):
    base_url: str
    version: str
    beta_version: str
    scope: str
    resource_app_id: str
    paths: dict[str, str]


class AzureEndpoints(_Frozen):
    arm_base_url: str
    arm_api_version: str
    diagnostic_settings_api_version: str
    tenants_api_version: str
    arm_scope: str
    log_analytics_scope: str
    paths: dict[str, str]


class Portal(_Frozen):
    base_url: str
    application: str
    application_by_object: str
    enterprise_application: str
    user: str
    group: str
    audit_logs: str
    sign_in_logs: str


class ProtectedResourceMetadata(_Frozen):
    well_known_path: str


class Endpoints(_Frozen):
    graph: GraphEndpoints
    azure: AzureEndpoints
    authority: Authority
    portal: Portal
    protected_resource_metadata: ProtectedResourceMetadata


class DiagnosticCategory(_Frozen):
    name: str
    table: str
    minimum_licence: str
    description: str


class SignInKind(_Frozen):
    graph_filter: str
    diagnostic_category: str
    kql_template: str
    graph_beta: bool = False


class LogQuery(_Frozen):
    graph_filter_template: str
    diagnostic_category: str
    kql_template: str
    graph_supported: bool = True


class LogDefaults(_Frozen):
    lookback_hours: int
    row_limit: int


class Tables(_Frozen):
    diagnostic_categories: tuple[DiagnosticCategory, ...]
    audit_categories: dict[str, str]
    sign_in_kinds: dict[str, SignInKind]
    log_queries: dict[str, LogQuery]
    workspace_id: str = ""
    defaults: LogDefaults


class HttpSettings(_Frozen):
    connect_timeout_seconds: float
    read_timeout_seconds: float
    user_agent: str
    pool_connections: int
    pool_maxsize: int


class RetrySettings(_Frozen):
    total: int
    connect: int
    read: int
    status: int
    backoff_factor: float
    backoff_max_seconds: float
    respect_retry_after_header: bool
    status_forcelist: tuple[int, ...]
    allowed_methods: tuple[str, ...]


class NetworkSettings(_Frozen):
    trust_environment: bool
    verify_tls: bool
    proxy_variables: tuple[str, ...]
    no_proxy_variables: tuple[str, ...]
    ca_bundle_variables: tuple[str, ...]
    ca_directory_variables: tuple[str, ...]


class ConcurrencySettings(_Frozen):
    max_workers: int


class PagingSettings(_Frozen):
    page_size: int
    max_pages: int
    max_objects: int = 2000
    no_page_size: tuple[str, ...] = ()


class Retry(_Frozen):
    http: HttpSettings
    retry: RetrySettings
    network: NetworkSettings
    concurrency: ConcurrencySettings
    paging: PagingSettings


class ExpirySettings(_Frozen):
    warning_days: int


class TimestampDisplay(_Frozen):
    decimals: int
    zone: str


class Display(_Frozen):
    timestamp: TimestampDisplay
    guest_marker: str
    wrapping_columns: tuple[str, ...]
    colours: dict[str, str]


class FindingRule(_Frozen):
    severity: str
    detail: str
    remediation: str
    docs_url: str


class FindingRules(_Frozen):
    audit_failure_results: tuple[str, ...]
    insecure_redirect_scheme: str
    local_hosts: tuple[str, ...]
    no_owner: FindingRule
    insecure_redirect: FindingRule
    assignment_required: FindingRule
    disabled_principal: FindingRule
    token_version_one: FindingRule


class Classification(_Frozen):
    service_principal_types: dict[str, str]
    single_sign_on_modes: dict[str, str]
    gallery_tags: tuple[str, ...]
    integrated_app_tag: str
    credential_types: dict[str, str]
    target_types: dict[str, str]
    first_party_owner_tenants: tuple[str, ...]
    audiences: dict[str, str]


class Fields(_Frozen):
    application: dict[str, str]
    service_principal: dict[str, str]
    credential: dict[str, str]
    sign_in: dict[str, str]
    audit: dict[str, str]
    expiry: ExpirySettings
    display: Display
    findings: FindingRules
    classification: Classification


class RedactionPattern(_Frozen):
    name: str
    regex: str


class Redaction(_Frozen):
    placeholder: str
    keys: tuple[str, ...]
    patterns: tuple[RedactionPattern, ...]


class SurfaceLogging(_Frozen):
    format: str | None = None
    destination: str | None = None


class Logging(_Frozen):
    level: str
    format: str
    destination: str
    quiet_loggers: dict[str, str] = {}
    surfaces: dict[str, SurfaceLogging]
    context_fields: tuple[str, ...]
    redaction: Redaction


class CredentialFileSettings(_Frozen):
    directory: str
    filename: str
    required_directory_mode: str
    required_file_mode: str
    keys: dict[str, str]


class EnvironmentSettings(_Frozen):
    client_id: str
    secret: str
    tenant_id: str


class SourceSettings(_Frozen):
    order: tuple[str, ...]
    enabled: dict[str, bool]
    identity_kind: dict[str, str]


class Credentials(_Frozen):
    file: CredentialFileSettings
    environment: EnvironmentSettings
    sources: SourceSettings


class TransportSettings(_Frozen):
    host: str
    port: int
    path: str
    base_url: str


class CorsSettings(_Frozen):
    allowed_origins: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    allowed_headers: tuple[str, ...]
    allow_credentials: bool


class RateLimitSettings(_Frozen):
    enabled: bool
    requests_per_second: float
    burst: int


class AuthorisationSettings(_Frozen):
    identifier_uri: str
    identifier_uri_template: str
    required_scopes: tuple[str, ...]
    strict_audience: bool
    resource_name: str
    resource_documentation: str


class ProtocolSettings(_Frozen):
    expected_version: str


class ServerEnvironment(_Frozen):
    tenant_id: str
    client_id: str
    identifier_uri: str
    base_url: str


class Server(_Frozen):
    transport: TransportSettings
    health_path: str
    cors: CorsSettings
    rate_limit: RateLimitSettings
    authorisation: AuthorisationSettings
    protocol: ProtocolSettings
    environment: ServerEnvironment


class ErrorEntry(_Frozen):
    meaning: str
    remediation: str
    docs_url: str
    likely_cause: str | None = None


class ErrorCodes(_Frozen):
    defaults: ErrorEntry
    errors: dict[str, ErrorEntry]


class GraphPermission(_Frozen):
    name: str
    app_role_id: str
    consent: str
    required: bool
    purpose: str
    privileged: bool = False


class DirectoryRole(_Frozen):
    name: str
    template_id: str
    sufficient: bool | str


class CapabilityRequirement(_Frozen):
    graph_permission: str | None = None
    diagnostic_category: str | None = None
    licence: str | None = None
    azure_role: str | None = None


class Capability(_Frozen):
    id: str
    requires: CapabilityRequirement
    remediation: str
    docs_url: str


class AppTypeRule(_Frozen):
    name: str
    when: dict[str, Any]
    description: str


class AppTypeVocabulary(_Frozen):
    status: str
    derived_from: str


class Provisioning(_Frozen):
    platform_types: tuple[str, ...]
    app_type_vocabulary: AppTypeVocabulary
    app_types: tuple[AppTypeRule, ...]
    outside_the_vocabulary: dict[str, str]


class Licences(_Frozen):
    p2_service_plans: tuple[str, ...]
    p1_service_plans: tuple[str, ...]
    free_label: str


class Capabilities(_Frozen):
    graph_permissions: tuple[GraphPermission, ...]
    delegated_equivalents: tuple[str, ...]
    directory_roles: tuple[DirectoryRole, ...]
    capabilities: tuple[Capability, ...]
    provisioning: Provisioning
    licences: Licences


class Config(_Frozen):
    """Every configuration file, validated, plus the directory they came from."""

    root: Path
    endpoints: Endpoints
    tables: Tables
    retry: Retry
    fields: Fields
    logging: Logging
    credentials: Credentials
    server: Server
    error_codes: ErrorCodes
    capabilities: Capabilities


def candidate_directories(explicit: Path | None = None) -> tuple[Path, ...]:
    """Return the directories to search for configuration, in order.

    The environment variable comes first, then configuration packaged inside
    the installed distribution, then the repository directory, which is what a
    development checkout uses. An explicit path is not a candidate: it is
    required, and :func:`find_config_dir` fails rather than searching past it.
    """
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(Path(explicit))
    from_environment = os.environ.get(CONFIG_DIR_VARIABLE)
    if from_environment:
        candidates.append(Path(from_environment))
    candidates.append(Path(__file__).resolve().parent / PACKAGED_CONFIG_DIRNAME)
    candidates.append(Path(__file__).resolve().parents[2] / "config")
    return tuple(candidates)


def find_config_dir(explicit: Path | None = None) -> Path:
    """Return the directory that holds configuration.

    A directory named explicitly is required rather than preferred. Falling
    through to another directory after the engineer named one would answer a
    question they did not ask.
    """
    if explicit is not None:
        named = Path(explicit)
        if (named / SENTINEL_FILE).is_file():
            return named
        raise ConfigError(
            f"The configuration directory {named} does not hold {SENTINEL_FILE}."
        )
    candidates = candidate_directories()
    for candidate in candidates:
        if (candidate / SENTINEL_FILE).is_file():
            return candidate
    searched = ", ".join(str(path) for path in candidates)
    raise ConfigError(
        f"No configuration directory found. Searched {searched}. "
        f"Set {CONFIG_DIR_VARIABLE} to the directory holding {SENTINEL_FILE}."
    )


def read_yaml(path: Path) -> dict[str, Any]:
    """Parse one YAML file into a mapping."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"Cannot read {path}: {error}") from error
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ConfigError(f"{path.name} is not valid YAML: {error}") from error
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name} must contain a mapping at the top level.")
    return data


def read_text_file(path: Path) -> str:
    """Return the contents of a text file inside the configuration directory."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"Cannot read {path}: {error}") from error


def load_kql(name: str, config: Config) -> str:
    """Return one KQL template by file name, without its extension."""
    path = config.root / "kql" / f"{name}.kql"
    if not path.is_file():
        available = sorted(p.stem for p in (config.root / "kql").glob("*.kql"))
        raise ConfigError(
            f"No KQL template named {name}. Available templates: {available}."
        )
    return read_text_file(path)


#: Characters that end a KQL string literal or start an escape inside one.
KQL_ESCAPES = {"\\": "\\\\", '"': '\\"', "'": "\\'"}

#: Control characters have no place in a query parameter.
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")

#: A parameter longer than this is a mistake or an attack, not a name.
MAX_PARAMETER = 512


def kql_literal(value: str) -> str:
    """Return a value safe to place inside a quoted KQL string.

    The templates place parameters inside double quotes. A quote or a backslash
    would end or extend the literal, letting a value rewrite the predicate it
    was meant to be matched by, and KQL can express a great deal more than a
    filter. Control characters are removed and the length is bounded.
    """
    cleaned = CONTROL_CHARACTERS.sub("", value)[:MAX_PARAMETER]
    return "".join(KQL_ESCAPES.get(character, character) for character in cleaned)


def kql_parameter(value: object) -> object:
    """Return one parameter ready for substitution.

    A number is coerced, so a template expecting a row count cannot be handed a
    fragment of query. Anything else is escaped as a string.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int | float):
        return value
    return kql_literal(str(value))


def render_kql(template: str, parameters: dict[str, object]) -> str:
    """Substitute named parameters into a KQL template.

    Queries are never assembled by concatenation, and every value is escaped
    here rather than at the call sites, because a call site is a place to
    forget.
    """
    escaped = {name: kql_parameter(value) for name, value in parameters.items()}
    try:
        return template.format(**escaped)
    except KeyError as error:
        raise ConfigError(
            f"KQL template needs a parameter that was not supplied: {error}."
        ) from error


def build_config(directory: Path) -> Config:
    """Validate every configuration file in one directory."""
    try:
        return Config.model_validate(
            {
                "root": directory,
                "endpoints": read_yaml(directory / "endpoints.yaml"),
                "tables": read_yaml(directory / "tables.yaml"),
                "retry": read_yaml(directory / "retry.yaml"),
                "fields": read_yaml(directory / "fields.yaml"),
                "logging": read_yaml(directory / "logging.yaml"),
                "credentials": read_yaml(directory / "credentials.yaml"),
                "server": read_yaml(directory / "server.yaml"),
                "error_codes": read_yaml(directory / "error-codes.yaml"),
                "capabilities": read_yaml(directory / "capabilities.yaml"),
            }
        )
    except ValidationError as error:
        raise ConfigError(
            f"Configuration in {directory} failed validation:\n{error}"
        ) from error


@lru_cache(maxsize=8)
def _load_cached(directory: Path) -> Config:
    """Load and cache one configuration directory."""
    return build_config(directory)


def load_config(explicit: Path | None = None) -> Config:
    """Return the validated configuration, loading it at most once per directory."""
    return _load_cached(find_config_dir(explicit))


def clear_cache() -> None:
    """Forget every cached configuration. Used by the test suite."""
    _load_cached.cache_clear()
