# Credentials and security

## The credential contract

Reuse it exactly. Do not change it.

- Credentials live at `~/.entra/provisioner-credentials.json`.
- The JSON keys are exactly `ClientID`, `Secret` and `TenantID`.
- The file mode must be 0600. The directory `~/.entra` must be 0700.
- entrascope validates both at startup by taking `st_mode` masked with `0o777`
  and comparing. If either is group or world accessible it refuses to run and
  prints the exact `chmod` that fixes it, without revealing the secret.
- Refusing means refusing. A credential file that is there and unsafe stops the
  command even when another source could have answered, because working around
  it would leave a secret readable by others while the tool carried on as
  though nothing were wrong. A file that is simply absent is not a
  misconfiguration and is passed over quietly. Naming another source with
  `--auth` is the deliberate act that leaves the file alone.
- An alternative filename inside `~/.entra` may be named in configuration.
- The secret is never logged and never printed.

## Authentication sources

Four sources, resolved in this order unless `--auth` names one explicitly. The
active source is reported at the top of the doctor report and attached to every
log record, so it is always obvious which identity produced a result.

| Order | `--auth` | Mechanism | Identity |
| --- | --- | --- | --- |
| 1 | `file` | the credential file, client credentials flow | application |
| 2 | `env` | `ARM_CLIENT_ID`, `ARM_CLIENT_SECRET`, `ARM_TENANT_ID` | application |
| 3 | `azure-cli` | `AzureCliCredential`, the session from `az login` | delegated user |
| 4 | `default` | `DefaultAzureCredential` | varies |

When resolution passes a source over, the reason is carried on the answer and
printed with any later failure, along with the identity that did answer. A
source that was expected to answer and quietly did not is the commonest
confusion there is.

The Azure CLI source needs no credential file, no client secret and no
application registration. Because the token is delegated it carries the
engineer's own identity, so authorisation comes from directory roles rather
than from Graph application permissions, and Global Reader, Security Reader or
Reports Reader covers the read surface. Some Graph scopes are not pre
authorised for the Azure CLI client in every tenant, so where a scope is
refused entrascope names the missing scope rather than failing opaquely. It is
implemented with `AzureCliCredential` rather than by shelling out, so caching
and refresh are the library's concern.

Unattended operation and the remote MCP server use the application sources. A
delegated CLI session is not present in a container.

## Forward proxies and certificate trust

entrascope must work unchanged on a corporate network, which means honouring a
forward web proxy and trusting a private certificate authority. Both are read
from the environment, and the variable names live in the `network` section of
`config/retry.yaml` so that a site with different conventions can add its own.

Proxies. `HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY`, in either case, with
`NO_PROXY` for the exceptions. requests honours these on its own when the
session trusts the environment, and entrascope resolves them explicitly as
well, so that `doctor` can report exactly which proxy is in force. An engineer
diagnosing a failure behind a proxy needs to see that before anything else
makes sense.

Certificate trust, in this order:

1. `ENTRASCOPE_CA_BUNDLE`, for a bundle that applies to this tool alone.
2. `REQUESTS_CA_BUNDLE`, which requests recognises natively.
3. `SSL_CERT_FILE`, the OpenSSL convention, which requests does not read.
4. `CURL_CA_BUNDLE`.
5. `SSL_CERT_DIR`, a directory of hashed certificates, used when no bundle file
   is named.

The first variable that is set and names a file that exists wins. A variable
that points at nothing falls through to the next, and finally to the
certificate bundle that requests ships. Verification is never silently
disabled by a missing or wrong path. Turning it off is a deliberate change to
`verify_tls` in configuration, and `doctor` reports it as a failed check with
the remediation.

The same setting reaches azure-identity and azure-monitor-query, which sit on
azure-core and take it as `connection_verify`, so the token endpoint and the
Log Analytics workspace are trusted the same way as Microsoft Graph. The Azure
CLI credential is the exception: it holds its own session and its own proxy and
certificate configuration, so nothing is passed through to it.

## Redaction

Redaction is a logging filter, not a habit. It is installed once by
`entrascope.logger` and applies to every record from every module, walking
structures and replacing any value whose key is listed in `logging.yaml` and
any value matching the bearer token or JSON web token patterns. Rendering
applies the same function before writing a table or a JSON payload.

A test drives every command and every MCP tool with a sentinel secret and
asserts the sentinel appears in no output stream and no log record.

## Values that reach a query

Anything an engineer types can end up inside a Microsoft Graph filter or a
Kusto query, and both are languages. A value is matched by a query; it does not
get to rewrite one.

- OData literals are escaped by doubling a single quote, in `graph.odata_literal`,
  which every filter goes through.
- Kusto values are escaped where the template is rendered, in
  `config.render_kql`, rather than at the call sites, because a call site is a
  place to forget. Numbers are coerced, so a template expecting a row count
  cannot be handed a fragment of query. Kusto expresses a great deal more than
  a filter, so this one matters most.
- Control characters are removed and lengths are bounded in both, because
  neither belongs in a name or an identifier.

## Values that reach a terminal

A display name in a directory is somebody else's input, and a terminal obeys
escape sequences. Control characters are removed from every rendered value. In
the plain format a newline or a tab is replaced too, because there one line is
one record and one tab is one column, so either would forge a row.

## Local MCP server guidance

A stdio MCP server runs with the privileges of the user who launched it, and
stdio transport has no OAuth. Therefore:

- the user must consent explicitly before the server is installed or run,
- credentials come from the environment or the credential file, never from a
  tool argument,
- tool output carries no secret,
- every tool validates its input,
- the server reads. It has no tool that changes the directory.

## Remote MCP server

The rules are in `mcp-server.md`. The two that matter most: the server
validates that a token was issued for it, and the server never forwards the
caller's token to Microsoft Graph.
