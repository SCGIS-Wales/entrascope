# Credentials and security

## The credential contract

Reuse it exactly. Do not change it.

- Credentials live at `~/.entra/provisioner-credentials.json`.
- The JSON keys are exactly `ClientID`, `Secret` and `TenantID`.
- The file mode must be 0600. The directory `~/.entra` must be 0700.
- entrascope validates both at startup by taking `st_mode` masked with `0o777`
  and comparing. If either is group or world accessible it refuses to run and
  prints the exact `chmod` that fixes it, without revealing the secret.
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

## Redaction

Redaction is a logging filter, not a habit. It is installed once by
`entrascope.logger` and applies to every record from every module, walking
structures and replacing any value whose key is listed in `logging.yaml` and
any value matching the bearer token or JSON web token patterns. Rendering
applies the same function before writing a table or a JSON payload.

A test drives every command and every MCP tool with a sentinel secret and
asserts the sentinel appears in no output stream and no log record.

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
