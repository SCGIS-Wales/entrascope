# MCP server design and authorisation

## Protocol revision

The steering research set the build target at revision 2025-11-25 and noted a
2026-07-28 revision scheduled for publication. entrascope does not assert which
revision is live. Phase 8 reads the protocol version that the installed FastMCP
actually negotiates, records it here, and asserts it in a test so that a
dependency bump which changes the negotiated revision fails the build rather
than changing behaviour silently.

Transport for the remote surface is Streamable HTTP. The deprecated HTTP with
server sent events transport is not implemented.

## Three surfaces, one core

**A. The command line.** Authenticates to Graph and Azure Monitor through one
of the four sources in `credentials-and-security.md`. Application permissions
when unattended, delegated permissions when acting as a signed in
administrator and the operation should be constrained to that person's
directory role scope.

**B. The local stdio server.** No OAuth, because stdio has none. Credentials
come from the environment or the credential file. It runs with the privileges
of the user who launched it, so explicit consent, least privilege, no secret in
tool output and input validation on every tool.

**C. The remote HTTP server.** An OAuth 2.1 protected resource that validates
Entra issued JSON web tokens.

## What surface C must do

- Serve OAuth 2.0 protected resource metadata per RFC 9728 at
  `/.well-known/oauth-protected-resource`, listing the Entra v2.0 issuer as the
  authorization server and the supported scopes.
- Return 401 with a `WWW-Authenticate` header whose `resource_metadata`
  parameter points at that document, on a missing or invalid token.
- Validate `iss`, `aud`, `exp`, `nbf`, `azp`, and `scp` for delegated callers
  or `roles` for application callers.
- Compare `aud` against the configured application id URI, not against the
  client id.
- Never accept a token that was not issued for it.
- Never forward the caller's token to Microsoft Graph.

Proof of the last point is a test, not a comment. A transport level assertion
checks that no request to the Graph host carries the caller's token.

Clients are responsible for PKCE and for sending the RFC 8707 `resource`
parameter, set to the canonical URI of this server, in both the authorization
and the token request. Audience binding is what prevents token passthrough and
the confused deputy problem.

## Registration and discovery

Entra supports neither dynamic client registration nor client id metadata
documents. Under revision 2025-11-25 dynamic client registration is only a MAY
and client id metadata documents are preferred, so entrascope uses
pre-registered clients and pure token verification. An OAuth proxy would be
required to support arbitrary third party clients, and that is out of scope
until there is a requirement for it.

Authorization server metadata discovery is available both through RFC 8414 and
through OpenID Connect Discovery 1.0.

## Calling Graph after authenticating the caller

Two correct patterns. entrascope uses the first.

1. **Separate service identity.** The server calls Graph with its own client
   credentials and application permissions. Correct here because the data is
   tenant scoped rather than caller scoped, and because it keeps the caller's
   token out of every downstream call.
2. **On behalf of.** The server exchanges the caller's token for a downstream
   Graph token, preserving the caller's delegated access. FastMCP provides
   `EntraOBOToken` for this. It needs delegated permissions, admin consent and
   additional authorize scopes, and it is only appropriate when results must be
   filtered to the calling user's own access. It is out of scope until a
   requirement demands it.

## Configuring Entra as the authorization server

Register the server as an API application. Under Expose an API set the
application id URI, which defaults to `api://{client-id}`, and define a scope
such as `access_as_user`, plus application roles for application only callers.
Set `requestedAccessTokenVersion` to 2 in the manifest so that tokens are
version 2.0 and the issuer and audience formats match what the verifier
expects.

Issuer, JWKS and discovery URLs are templates in `config/endpoints.yaml`, one
set for version 2.0 and one for the version 1.0 issuer variant.

## FastMCP wiring

```python
# framework contract: FastMCP requires class based providers; keep all logic in
# free functions and treat these objects as configuration only.
from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.azure import AzureJWTVerifier
from pydantic import AnyHttpUrl


def build_auth(
    tenant_id: str,
    client_id: str,
    identifier_uri: str,
    required_scopes: list[str],
    base_url: str,
    issuer: str,
) -> RemoteAuthProvider:
    verifier = AzureJWTVerifier(
        client_id=client_id,
        tenant_id=tenant_id,
        required_scopes=required_scopes,
    )
    # framework contract: the Entra v2.0 audience is the application id URI and
    # not the client id GUID. Phase 8 confirms whether the installed FastMCP
    # exposes a public parameter for this before falling back to the private
    # attribute reported in PrefectHQ/fastmcp issues 3002 and 3729.
    verifier._audience = identifier_uri
    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[AnyHttpUrl(issuer)],
        base_url=base_url,
    )


def build_server(auth: RemoteAuthProvider) -> FastMCP:
    return FastMCP(name="entrascope", auth=auth)
```

The issuer and the application id URI come from configuration. Neither is a
literal in code.

## Deployment

Terminate TLS at a reverse proxy. Production base URLs and redirect URIs are
https. Bind to 0.0.0.0 inside the container and expose only through the proxy.
Serve `/healthz`. Restrict CORS to configured origins. Apply per client rate
limits. Log JSON lines carrying the correlation id and the token `azp` and
`sub`, and never the token itself or any secret. The container is a multi stage
build on `python:3.14-slim`, running as a non root user, with a read only
filesystem where possible.
