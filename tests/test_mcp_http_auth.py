"""Remote server authorisation tests.

Tokens are minted locally with an RS256 key pair generated in a fixture, and
the verifier's key cache is primed with the matching public key, so nothing
here needs a tenant or a network.

Three rules are proved: the server refuses a token that was not issued for it,
the audience must equal the configured application id URI, and the caller's
token never reaches Microsoft Graph.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import jwt
import pytest
import responses
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from entrascope.config import Config
from entrascope.mcp_http import (
    base_url,
    build_auth,
    build_server,
    build_verifier,
    check_protocol_version,
    cors_middleware,
    http_app,
    issuer_for,
    negotiated_protocol_version,
    rate_limit_middleware,
    server_identity,
)
from entrascope.models import ConfigError

TENANT = "bc96f6fe-1111-1111-1111-111111111111"
CLIENT = "f26d27d1-1111-1111-1111-111111111111"
IDENTIFIER = f"api://{CLIENT}"
BASE = "https://entrascope.example.invalid"
KID = "test-key"

ENVIRON = {
    "ENTRASCOPE_TENANT_ID": TENANT,
    "ENTRASCOPE_CLIENT_ID": CLIENT,
    "ENTRASCOPE_BASE_URL": BASE,
}


@pytest.fixture(scope="module")
def keys() -> tuple[str, str]:
    """Generate an RS256 key pair once for the module."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_pem, public_pem


def mint(
    private_pem: str,
    *,
    audience: str = IDENTIFIER,
    issuer: str | None = None,
    scopes: str = "access_as_user",
    expires_in: int = 3600,
    subject: str = "user-1",
) -> str:
    """Mint a token carrying the claims the verifier reads."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "aud": audience,
        "iss": issuer or f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "sub": subject,
        "azp": "a-registered-client",
        "tid": TENANT,
    }
    if scopes:
        claims["scp"] = scopes
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": KID})


def primed_verifier(config: Config, public_pem: str) -> Any:
    """Return a verifier whose key cache already holds the test public key."""
    verifier = build_verifier(config, TENANT, CLIENT, IDENTIFIER)
    verifier._jwks_cache = {KID: public_pem, "_default": public_pem}
    verifier._jwks_cache_time = time.time()
    return verifier


@pytest.fixture
def client(config: Config) -> Iterator[TestClient]:
    """Return a test client over the remote application."""
    with TestClient(http_app(config, ENVIRON)) as running:
        yield running


def test_protocol_version_pinned(config: Config) -> None:
    """The negotiated revision is the one this server was built against."""
    assert negotiated_protocol_version() == config.server.protocol.expected_version
    assert check_protocol_version(config) == "2025-11-25"


def test_a_changed_protocol_revision_fails_loudly(config: Config) -> None:
    """A dependency bump that changes the revision must not pass quietly."""
    protocol = config.server.protocol.model_copy(
        update={"expected_version": "1999-01-01"}
    )
    changed = config.model_copy(
        update={"server": config.server.model_copy(update={"protocol": protocol})}
    )
    with pytest.raises(ConfigError, match="negotiate protocol revision"):
        check_protocol_version(changed)


def test_the_identity_comes_from_the_environment(config: Config) -> None:
    """A container is configured without a credential file."""
    assert server_identity(config, ENVIRON) == (TENANT, CLIENT, IDENTIFIER)


def test_the_identifier_uri_defaults_to_the_configured_template(config: Config) -> None:
    """The Entra default is api:// followed by the client id, from configuration."""
    template = config.server.authorisation.identifier_uri_template
    assert template.format(client_id=CLIENT) == IDENTIFIER


def test_a_missing_identity_is_explained(config: Config) -> None:
    """Without a tenant and a client the server says which variables to set."""
    with pytest.raises(ConfigError, match="ENTRASCOPE_TENANT_ID"):
        server_identity(config, {"HOME": "/nowhere"})


def test_a_missing_base_url_falls_back_to_this_machine(config: Config) -> None:
    """Refusing to start helps nobody trying the server out locally.

    The loopback address is only ever right on this machine, which is why it
    is safe to assume and why the server says out loud that it assumed it.
    """
    assumed = base_url(config, {})
    assert assumed == f"http://localhost:{config.server.transport.port}"


def test_the_base_url_loses_a_trailing_slash(config: Config) -> None:
    """One canonical form, because it appears in the metadata."""
    assert base_url(config, {"ENTRASCOPE_BASE_URL": f"{BASE}/"}) == BASE


def test_http_wrong_audience_is_configured_out(config: Config) -> None:
    """The audience is narrowed to the application id URI, as the rule requires.

    FastMCP accepts either the client id or the URI by default. The steering
    rule is stricter, and this is the public attribute that enforces it.
    """
    verifier = build_verifier(config, TENANT, CLIENT, IDENTIFIER)
    assert verifier.audience == IDENTIFIER
    assert config.server.authorisation.strict_audience is True


def test_the_broader_audience_can_be_restored(config: Config) -> None:
    """A pre-registered client that cannot request the URI form is catered for."""
    authorisation = config.server.authorisation.model_copy(
        update={"strict_audience": False}
    )
    relaxed = config.model_copy(
        update={
            "server": config.server.model_copy(update={"authorisation": authorisation})
        }
    )
    verifier = build_verifier(relaxed, TENANT, CLIENT, IDENTIFIER)
    assert verifier.audience == [CLIENT, IDENTIFIER]


def test_the_issuer_comes_from_configuration(config: Config) -> None:
    """The version 2.0 issuer template is configuration, not a literal."""
    assert issuer_for(config, TENANT).endswith(f"/{TENANT}/v2.0")
    verifier = build_verifier(config, TENANT, CLIENT, IDENTIFIER)
    assert verifier.issuer == issuer_for(config, TENANT)


def test_the_required_scopes_come_from_configuration(config: Config) -> None:
    """A caller must present the configured scope."""
    verifier = build_verifier(config, TENANT, CLIENT, IDENTIFIER)
    assert verifier.required_scopes == list(config.server.authorisation.required_scopes)


async def test_http_valid_token(config: Config, keys: tuple[str, str]) -> None:
    """A token with the right audience, issuer and scope is accepted."""
    private_pem, public_pem = keys
    verifier = primed_verifier(config, public_pem)
    accepted = await verifier.verify_token(mint(private_pem))
    assert accepted is not None
    assert accepted.client_id


async def test_http_wrong_audience(config: Config, keys: tuple[str, str]) -> None:
    """A token minted for another resource is refused."""
    private_pem, public_pem = keys
    verifier = primed_verifier(config, public_pem)
    other = await verifier.verify_token(
        mint(private_pem, audience="api://some-other-application")
    )
    assert other is None


async def test_the_client_id_alone_is_not_an_acceptable_audience(
    config: Config, keys: tuple[str, str]
) -> None:
    """Under the strict rule the bare client id is refused."""
    private_pem, public_pem = keys
    verifier = primed_verifier(config, public_pem)
    assert await verifier.verify_token(mint(private_pem, audience=CLIENT)) is None


async def test_http_wrong_issuer(config: Config, keys: tuple[str, str]) -> None:
    """A token from another tenant is refused."""
    private_pem, public_pem = keys
    verifier = primed_verifier(config, public_pem)
    foreign = await verifier.verify_token(
        mint(private_pem, issuer="https://login.microsoftonline.com/other/v2.0")
    )
    assert foreign is None


async def test_http_expired_token(config: Config, keys: tuple[str, str]) -> None:
    """An expired token is refused."""
    private_pem, public_pem = keys
    verifier = primed_verifier(config, public_pem)
    assert await verifier.verify_token(mint(private_pem, expires_in=-60)) is None


async def test_http_missing_scope(config: Config, keys: tuple[str, str]) -> None:
    """A token without the required scope is refused."""
    private_pem, public_pem = keys
    verifier = primed_verifier(config, public_pem)
    assert await verifier.verify_token(mint(private_pem, scopes="")) is None


async def test_a_token_signed_by_another_key_is_refused(
    config: Config, keys: tuple[str, str]
) -> None:
    """A token we cannot verify is refused rather than trusted."""
    _, public_pem = keys
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    verifier = primed_verifier(config, public_pem)
    assert await verifier.verify_token(mint(other_pem)) is None


def test_http_401_no_token(client: TestClient) -> None:
    """An unauthenticated request is refused."""
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert response.status_code == 401


def test_www_authenticate_header(client: TestClient) -> None:
    """The refusal points at the protected resource metadata, per RFC 9728."""
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    header = response.headers.get("www-authenticate", "")
    assert "Bearer" in header
    assert "resource_metadata=" in header
    assert "oauth-protected-resource" in header


def metadata_path(config: Config) -> str:
    """Return the protected resource metadata path for this server.

    RFC 9728 scopes the document to the resource path, so a server mounted at
    /mcp publishes it under /.well-known/oauth-protected-resource/mcp.
    """
    well_known = config.endpoints.protected_resource_metadata.well_known_path
    return f"{well_known}{config.server.transport.path}"


def test_protected_resource_metadata(client: TestClient, config: Config) -> None:
    """The metadata names the authorization server, the resource and the scopes."""
    response = client.get(metadata_path(config))
    assert response.status_code == 200
    body = response.json()
    assert body["resource"].startswith(BASE)
    assert any(TENANT in server for server in body["authorization_servers"])
    assert any(scope.startswith(IDENTIFIER) for scope in body["scopes_supported"])


def test_the_refusal_points_at_the_document_that_exists(
    client: TestClient, config: Config
) -> None:
    """The URL in the refusal header is the one that answers."""
    refusal = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    advertised = refusal.headers["www-authenticate"].split('resource_metadata="')[1]
    advertised = advertised.split('"')[0]
    assert advertised == f"{BASE}{metadata_path(config)}"
    assert client.get(metadata_path(config)).status_code == 200


def test_healthz(client: TestClient) -> None:
    """The health endpoint answers without a token."""
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["protocol"] == negotiated_protocol_version()


def test_cors_is_closed_unless_origins_are_named(config: Config) -> None:
    """No cross origin request is allowed until an origin is configured."""
    assert cors_middleware(config) == []
    cors = config.server.cors.model_copy(
        update={"allowed_origins": ("https://a.invalid",)}
    )
    opened = config.model_copy(
        update={"server": config.server.model_copy(update={"cors": cors})}
    )
    assert len(cors_middleware(opened)) == 1


def test_rate_limiting_is_configured(config: Config) -> None:
    """Rate limiting is on by default and can be switched off."""
    assert rate_limit_middleware(config) is not None
    limits = config.server.rate_limit.model_copy(update={"enabled": False})
    off = config.model_copy(
        update={"server": config.server.model_copy(update={"rate_limit": limits})}
    )
    assert rate_limit_middleware(off) is None


def test_the_server_builds_with_authorisation(config: Config) -> None:
    """The server is built as a resource server, with tools and health."""
    server = build_server(config, ENVIRON)
    assert server.name == "entrascope"
    auth = build_auth(config, ENVIRON)
    assert auth.token_verifier is not None


@responses.activate
def test_no_token_passthrough(
    config: Config, monkeypatch: pytest.MonkeyPatch, keys: tuple[str, str]
) -> None:
    """The caller's token never reaches Microsoft Graph.

    Graph is called with the server's own credentials, so a request carrying a
    caller token would be a confused deputy. This asserts it at the transport,
    not in a comment.
    """
    private_pem, _ = keys
    caller_token = mint(private_pem)

    # framework contract: azure-core defines the credential and token shapes.
    class Token:
        token = "the-servers-own-token"
        expires_on = 4_102_444_800

    class Credential:
        def get_token(self, *scopes: str, **kwargs: object) -> object:
            return Token()

    monkeypatch.setattr(
        "entrascope.mcp_tools.resolve_auth",
        lambda config, requested=None: (None, Credential()),
    )
    responses.add(
        responses.GET,
        "https://graph.microsoft.com/v1.0/applications",
        json={"value": []},
        status=200,
    )

    from entrascope.discovery import discover_applications
    from entrascope.mcp_tools import credential_factory, graph_session

    session, _ = graph_session(config, credential_factory(config)())
    discover_applications(session, config, with_details=False)
    session.close()

    sent = responses.calls[0].request.headers["Authorization"]
    assert sent == "Bearer the-servers-own-token"
    assert caller_token not in sent


def test_the_http_server_is_reachable_from_the_command_line() -> None:
    """The serve group documents the remote server and its rules."""
    from click.testing import CliRunner

    from entrascope.cli import cli

    result = CliRunner().invoke(cli, ["serve", "http", "--help"], obj={})
    assert result.exit_code == 0
    normalised = " ".join(result.output.split())
    assert "never forwarded to Microsoft Graph" in normalised
    assert "--host" in result.output
    assert "--port" in result.output


def test_the_web_server_installs_no_logging_of_its_own(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One format on one stream.

    uvicorn resets the levels it owns and announces itself in a second format
    unless it is told to install no logging configuration.
    """
    recorded: dict[str, Any] = {}

    # framework contract: FastMCP expresses the server as an object, so the
    # double must present the same run method.
    class Recording:
        def run(self, **kwargs: Any) -> None:
            recorded.update(kwargs)

    monkeypatch.setattr("entrascope.mcp_http.build_server", lambda *a, **k: Recording())
    from entrascope.mcp_http import run

    run(config, ENVIRON)
    assert recorded["uvicorn_config"] == {"log_config": None}
    assert recorded["show_banner"] is False
    assert recorded["host"] == config.server.transport.host
    assert recorded["port"] == config.server.transport.port


def test_a_plain_canonical_uri_is_refused(config: Config) -> None:
    """It is published in the metadata and clients bind their tokens to it."""
    with pytest.raises(ConfigError, match="not https"):
        base_url(config, {"ENTRASCOPE_BASE_URL": "http://entrascope.example.invalid"})


def test_a_loopback_address_is_accepted(config: Config) -> None:
    """Somebody writing a client on their own machine needs no certificate."""
    for address in ("http://localhost:8000", "http://127.0.0.1:8000"):
        assert base_url(config, {"ENTRASCOPE_BASE_URL": address}) == address


def test_https_is_accepted(config: Config) -> None:
    """The ordinary case."""
    assert base_url(config, ENVIRON) == BASE


def test_a_correlation_id_from_the_wire_cannot_forge_a_log_line() -> None:
    """It appears on every line the request causes, so it must be plain."""
    from starlette.datastructures import Headers

    from entrascope.mcp_http import correlation_from

    class Asked:
        def __init__(self, value: str) -> None:
            self.headers = Headers({"x-correlation-id": value})

    plain = correlation_from(Asked("7f3c-1234:abc"))
    assert plain == "7f3c-1234:abc"
    forged = correlation_from(Asked("ok\nERROR the tenant was deleted"))
    assert "\n" not in forged
    assert forged != "ok\nERROR the tenant was deleted"
    assert correlation_from(Asked("x" * 200)) != "x" * 200
