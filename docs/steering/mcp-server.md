# MCP server design and authorisation

## Protocol revision

Verified against the installed libraries rather than assumed. FastMCP 3.4.7
resolves `mcp` 1.29.0, whose `LATEST_PROTOCOL_VERSION` is **2025-11-25**, which
is exactly the revision the research named as the build target. That value is
in `config/server.yaml` as `protocol.expected_version`, the server refuses to
start if the installed libraries negotiate anything else, and a test asserts
it. A dependency bump that changes the revision therefore fails the build
rather than changing behaviour silently.

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

## The tool surface

Nine tools, all read only, registered by one free function that both servers
call so the two surfaces cannot diverge:

| Tool | Purpose |
| --- | --- |
| `doctor` | every preflight check, with remediation |
| `discover_applications` | application registrations, filterable by type and by expiring credential |
| `discover_service_principals` | enterprise applications, managed identities and SAML applications |
| `audit_events` | directory changes to applications |
| `sign_ins` | sign ins of one kind, through Graph or through a workspace |
| `graph_activity` | Microsoft Graph requests, through a workspace only |
| `explain_error` | one error code or a message carrying one, no credentials needed |
| `list_error_codes` | every code, optionally searched |
| `sign_in_kinds` | the kinds `sign_ins` accepts |

Every tool returns the payload `render.py` produces, which is the same payload
the command line emits under `--output json`. A test asserts the two are
identical, because an assistant and an engineer must not be looking at
different answers to one question.

Tool descriptions that name a diagnostic category or an audit category read it
from configuration, so renaming one in `tables.yaml` updates what the assistant
is told.

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

The earlier research prescribed setting the private attribute
`verifier._audience`, citing two upstream issues. That is not needed and is not
what entrascope does. FastMCP 3.4.7 takes the application id URI as a public
parameter, `identifier_uri`, and then accepts **either** that or the bare client
id as the audience.

Accepting both is safe against another application's token, because both values
identify this application. It is nonetheless broader than the rule above, which
says the audience must equal the application id URI. So entrascope narrows it,
using `verifier.audience`, a public attribute, and `strict_audience` in
`config/server.yaml` can restore the broader behaviour for a pre-registered
client that cannot be made to request the URI form.

```python
def build_verifier(
    config: Config, tenant_id: str, client_id: str, identifier_uri: str
) -> AzureJWTVerifier:
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
```

The issuer and the application id URI come from configuration. Neither is a
literal in code.

## Where the metadata is served

RFC 9728 scopes the protected resource metadata to the resource path, so a
server mounted at `/mcp` publishes its document at
`/.well-known/oauth-protected-resource/mcp`, and the `resource_metadata`
parameter in the `WWW-Authenticate` header points there. A test asserts the URL
the refusal advertises is the URL that answers.

## Deployment

Terminate TLS at a reverse proxy. Production base URLs and redirect URIs are
https. Bind to 0.0.0.0 inside the container and expose only through the proxy.
Serve `/healthz`. Restrict CORS to configured origins. Apply per client rate
limits. Log JSON lines carrying the correlation id and the token `azp` and
`sub`, and never the token itself or any secret. The container is a multi stage
build on `python:3.14-slim`, running as a non root user, with a read only
filesystem where possible.
