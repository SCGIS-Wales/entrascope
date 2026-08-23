"""The remote MCP server, over Streamable HTTP.

An OAuth 2.1 protected resource that validates Entra issued bearer tokens. The
deprecated transport using server sent events is not implemented.

Three rules govern this module, and each is covered by a test:

1. The server never accepts a token that was not issued for it.
2. The audience claim must equal the configured application id URI.
3. The caller's token is never forwarded to Microsoft Graph. Graph is called
   with the server's own client credentials.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

import mcp.types
from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.azure import AzureJWTVerifier
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware
from pydantic import AnyHttpUrl
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from entrascope.config import Config, load_config
from entrascope.credentials import read_credential_file, resolve_auth
from entrascope.logger import configure_logging, get_logger, new_correlation_id
from entrascope.mcp_tools import (
    INSTRUCTIONS,
    SERVER_NAME,
    credential_factory,
    register_tools,
)
from entrascope.models import AuthSource, ConfigError, Credential, CredentialError

log = get_logger(__name__)

#: The surface name, which selects the logging format and destination.
SURFACE = "mcp_http"

#: Addresses that need no certificate, because nothing leaves the machine.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

#: Header a proxy uses to pass a correlation id through.
CORRELATION_HEADER = "x-correlation-id"

#: What a correlation id may look like when somebody else supplies one. Long
#: enough for a GUID with dashes and for the identifiers the Azure services
#: use, and nothing in it can forge a log line.
SAFE_CORRELATION = re.compile(r"[A-Za-z0-9._:-]{1,64}")


def negotiated_protocol_version() -> str:
    """Return the protocol revision the installed libraries negotiate."""
    return str(mcp.types.LATEST_PROTOCOL_VERSION)


def check_protocol_version(config: Config) -> str:
    """Confirm the negotiated revision is the one this server was built against.

    A dependency bump that changes the revision must fail loudly rather than
    change behaviour quietly.
    """
    expected = config.server.protocol.expected_version
    actual = negotiated_protocol_version()
    if actual != expected:
        raise ConfigError(
            f"The installed libraries negotiate protocol revision {actual}, and "
            f"this server was built against {expected}. Review the changes, then "
            "update expected_version in config/server.yaml."
        )
    return actual


def from_environment(name: str, environ: Mapping[str, str] | None = None) -> str:
    """Return one environment variable, or an empty string."""
    source = os.environ if environ is None else environ
    return source.get(name, "").strip()


def credential_or_none(config: Config) -> Credential | None:
    """Return the credential file contents, or None when there is no file."""
    try:
        return read_credential_file(config.credentials)
    except CredentialError:
        return None


def server_identity(
    config: Config, environ: Mapping[str, str] | None = None
) -> tuple[str, str, str]:
    """Return the tenant, client and application id URI this server presents.

    The environment wins, so a container is configured without a credential
    file. Otherwise the credential file supplies the tenant and client, which
    keeps a local run to one source of truth.
    """
    names = config.server.environment
    tenant = from_environment(names.tenant_id, environ)
    client = from_environment(names.client_id, environ)
    if not (tenant and client):
        credential = credential_or_none(config)
        tenant = tenant or (credential.tenant_id if credential else "")
        client = client or (credential.client_id if credential else "")
    if not (tenant and client):
        raise ConfigError(
            f"The remote server needs a tenant and a client. Set {names.tenant_id} "
            f"and {names.client_id}, or provide the credential file."
        )
    settings = config.server.authorisation
    identifier = (
        from_environment(names.identifier_uri, environ)
        or settings.identifier_uri
        or settings.identifier_uri_template.format(client_id=client)
    )
    return tenant, client, identifier


def base_url(config: Config, environ: Mapping[str, str] | None = None) -> str:
    """Return the canonical URI clients use to reach this server."""
    transport = config.server.transport
    configured = (
        from_environment(config.server.environment.base_url, environ)
        or transport.base_url
    )
    if not configured:
        # Refusing to start because nobody has said where the server will live
        # helps nobody who is trying it out on their own machine. The loopback
        # address is assumed, which is only ever right here, and said out loud
        # so that nothing is deployed under it by accident.
        configured = transport.local_base_url.format(port=transport.port)
        log.warning(
            "no canonical URI is set, so this server assumes %s. That address "
            "works on this machine only. In production set %s or base_url in "
            "config/server.yaml to the https address clients reach, because it "
            "appears in the protected resource metadata and clients bind their "
            "tokens to it",
            configured,
            config.server.environment.base_url,
        )
    trimmed = configured.rstrip("/")
    if not is_secure(trimmed):
        raise ConfigError(
            f"The canonical URI {trimmed} is not https. It is published in the "
            "protected resource metadata, and clients bind their tokens to it, "
            "so a plain address invites a token to be sent in clear.\n"
            "  Terminate TLS at a reverse proxy and set the https address "
            "here. A loopback address is accepted for local development."
        )
    return trimmed


def is_secure(url: str) -> bool:
    """Return whether a canonical URI is safe to publish.

    https always, or a loopback address, which is how somebody runs this on
    their own machine while writing a client.
    """
    if url.startswith("https://"):
        return True
    host = urlparse(url).hostname or ""
    return host in LOOPBACK_HOSTS


def build_verifier(
    config: Config, tenant_id: str, client_id: str, identifier_uri: str
) -> AzureJWTVerifier:
    """Build the token verifier, with the audience the steering rule requires.

    FastMCP 3.4.7 takes the application id URI as a public parameter and then
    accepts either that or the client id as the audience. The steering rule is
    stricter, so by default the audience is narrowed to the URI alone. That is
    a public attribute on the verifier, not the private one the earlier
    research described.
    """
    # framework contract: FastMCP requires class based providers. They are
    # configuration, and every decision here comes from config/server.yaml.
    verifier = AzureJWTVerifier(
        client_id=client_id,
        tenant_id=tenant_id,
        identifier_uri=identifier_uri,
        required_scopes=list(config.server.authorisation.required_scopes),
    )
    if config.server.authorisation.strict_audience:
        verifier.audience = identifier_uri
    return verifier


def issuer_for(config: Config, tenant_id: str) -> str:
    """Return the version 2.0 issuer for one tenant, from configuration."""
    return config.endpoints.authority.v2.issuer_template.format(tenant_id=tenant_id)


def build_auth(
    config: Config, environ: Mapping[str, str] | None = None
) -> RemoteAuthProvider:
    """Build the resource server: pure token verification, no proxy."""
    tenant_id, client_id, identifier_uri = server_identity(config, environ)
    settings = config.server.authorisation
    # framework contract: FastMCP requires class based providers.
    return RemoteAuthProvider(
        token_verifier=build_verifier(config, tenant_id, client_id, identifier_uri),
        authorization_servers=[AnyHttpUrl(issuer_for(config, tenant_id))],
        base_url=base_url(config, environ),
        resource_name=settings.resource_name,
        resource_documentation=AnyHttpUrl(settings.resource_documentation),
    )


def rate_limit_middleware(config: Config) -> RateLimitingMiddleware | None:
    """Build the per client rate limiting middleware, or None when it is off."""
    settings = config.server.rate_limit
    if not settings.enabled:
        return None
    # framework contract: FastMCP expresses middleware as a class.
    return RateLimitingMiddleware(
        max_requests_per_second=settings.requests_per_second,
        burst_capacity=settings.burst,
    )


def cors_middleware(config: Config) -> list[Middleware]:
    """Build the CORS middleware, restricted to the configured origins."""
    settings = config.server.cors
    if not settings.allowed_origins:
        return []
    # framework contract: Starlette expresses middleware as a class.
    return [
        Middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_origins),
            allow_methods=list(settings.allowed_methods),
            allow_headers=list(settings.allowed_headers),
            allow_credentials=settings.allow_credentials,
        )
    ]


def register_health(server: FastMCP, config: Config) -> FastMCP:
    """Register the health endpoint, which needs no token."""

    @server.custom_route(config.server.health_path, methods=["GET"])
    async def healthz(request: Request) -> Response:
        _ = request
        return JSONResponse(
            {
                "status": "ok",
                "name": SERVER_NAME,
                "protocol": negotiated_protocol_version(),
            }
        )

    return server


def correlation_from(request: Request) -> str:
    """Return the correlation id a proxy passed in, or a fresh one.

    What a caller sends is a caller's text, and it goes on to appear on every
    log line the request causes. A newline in it would forge a line and an
    escape sequence would move a cursor about in whatever is reading the log,
    so anything that is not a plain identifier is replaced rather than trusted.
    """
    supplied = request.headers.get(CORRELATION_HEADER, "").strip()
    if supplied and SAFE_CORRELATION.fullmatch(supplied):
        return supplied
    if supplied:
        log.debug("the correlation id supplied was not a plain identifier")
    return new_correlation_id()


def build_server(
    config: Config | None = None,
    environ: Mapping[str, str] | None = None,
    requested: AuthSource | None = None,
) -> FastMCP:
    """Build the remote server: tools, authorisation, health and rate limiting.

    Graph is called with the server's own identity, not the caller's token. The
    data is tenant scoped rather than caller scoped, so application permissions
    describe it correctly, and nothing the caller sends leaves this process.
    """
    settings = config or load_config()
    configure_logging(settings, surface=SURFACE)
    check_protocol_version(settings)
    auth = build_auth(settings, environ)
    # framework contract: FastMCP expresses a server as an object.
    server = FastMCP(name=SERVER_NAME, instructions=INSTRUCTIONS, auth=auth)
    limiter = rate_limit_middleware(settings)
    if limiter is not None:
        server.add_middleware(limiter)
    register_tools(server, settings, credential_factory(settings, requested), requested)
    register_health(server, settings)
    log.info(
        "remote server ready",
        extra={
            "surface": SURFACE,
            "protocol": negotiated_protocol_version(),
            "base_url": base_url(settings, environ),
        },
    )
    return server


def http_app(
    config: Config | None = None, environ: Mapping[str, str] | None = None
) -> Any:
    """Return the ASGI application, for a container or a test client."""
    settings = config or load_config()
    server = build_server(settings, environ)
    return server.http_app(
        path=settings.server.transport.path,
        middleware=cors_middleware(settings),
        transport="http",
    )


def run(config: Config | None = None, environ: Mapping[str, str] | None = None) -> None:
    """Run the remote server over Streamable HTTP.

    The web server is told to install no logging configuration of its own, so
    that everything on the stream is a JSON line from our own logger. Without
    that, uvicorn resets the levels it owns and announces its startup in a
    second format, which a log parser then has to cope with.
    """
    settings = config or load_config()
    transport = settings.server.transport
    build_server(settings, environ).run(
        transport="http",
        host=transport.host,
        port=transport.port,
        path=transport.path,
        show_banner=False,
        uvicorn_config={"log_config": None},
    )


def graph_identity(config: Config) -> str:
    """Describe the identity Graph is called with, for the log and the tests.

    Stated explicitly because the rule that matters most here is the one that
    is invisible in the code: the caller's token is never forwarded.
    """
    context, _ = resolve_auth(config)
    return context.description
