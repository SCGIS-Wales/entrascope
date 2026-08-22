# entrascope

Observability and diagnostics for Microsoft Entra ID and Azure Monitor, helping
engineers troubleshoot authentication and authorisation failures.

> Entra directory operations do not appear in the Azure subscription activity
> log. They are recorded in the Entra audit logs, under the category
> ApplicationManagement. entrascope reads them through Microsoft Graph and
> through Azure Monitor.

[![CI](https://github.com/SCGIS-Wales/entrascope/actions/workflows/ci.yml/badge.svg)](https://github.com/SCGIS-Wales/entrascope/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.14-blue)](https://www.python.org/downloads/)
[![Licence](https://img.shields.io/badge/licence-MIT-green)](LICENSE)

## What it does

- **Discovery.** Enumerate application registrations and enterprise
  applications of every type, and project sign in audience, redirect URIs,
  requested and granted permissions, owners, credentials and their expiry,
  federated identity credentials, SAML configuration and the assignment
  requirement.
- **Log interrogation.** Read Entra audit logs, interactive and non interactive
  user sign ins, service principal and managed identity sign ins, Microsoft
  Graph activity and provisioning logs.
- **Capability detection.** Report when the logging you need is not enabled,
  which licence tier it requires and how to switch it on.
- **Error explanation.** Map AADSTS and Microsoft Graph error codes to meaning,
  likely cause and remediation.

## Three surfaces, one core

| Surface | Transport | Authentication |
| --- | --- | --- |
| Command line | local | credential file, environment, Azure CLI or DefaultAzureCredential |
| Local MCP server | stdio | the same, no OAuth |
| Remote MCP server | Streamable HTTP | OAuth 2.1 resource server validating Entra tokens |

## Installation

```bash
pip install entrascope
```

From a clone, for development:

```bash
python3.14 -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

## Authentication

The quickest route needs nothing but an Azure CLI session:

```bash
az login
entrascope doctor --auth azure-cli
```

For unattended use, place client credentials at
`~/.entra/provisioner-credentials.json` with the keys `ClientID`, `Secret` and
`TenantID`. The file must be mode 0600 inside a directory of mode 0700, and
entrascope refuses to run otherwise.

## Using it

Run `entrascope` with no arguments and it tells you what it can do. Every group
and every command carries its own help and worked examples, so `--help` is
always the next step.

### Terminology, used the same way throughout

| Term | Meaning |
| --- | --- |
| application registration | what you register in Entra, the definition |
| enterprise application | the service principal, the instance in a tenant |
| delegated permission | acts as a signed in person, a `scp` claim |
| application permission | acts as itself, a `roles` claim |

### Knowing where you stand

```bash
entrascope whoami      # which tenant, which identity, what it may do
entrascope doctor      # can entrascope see what it needs
```

`whoami` answers the question every diagnosis starts with and most people get
wrong: the tenant by name and identifier, the tenants this identity can reach,
the permissions the token actually carries, the directory roles held, the
administrative units that bound them, and the conditional access policies in
force.

### Looking at one application

```bash
entrascope inspect                 # choose from a list, with / to search
entrascope inspect saml2           # by name
entrascope inspect d6bdb5c4-1722-4c63-930f-fa264d4778bc
entrascope inspect --type managed-identity
```

Shows the registration and the enterprise application together, as YAML,
coloured at a terminal and plain in a pipe: the scopes it exposes, the roles it
defines, what it asked for against what was actually consented, every URL it is
registered with, its credentials and their expiry, and its single sign on
configuration.

With no argument and a terminal to draw on, it offers the list. Move with the
arrow keys or with j and k, search with `/` as in vi, enter to open, q to stop.

### Diagnosing a failure

Start wide, then narrow. `investigate` gathers credentials, directory changes
and sign in failures, applies a set of rules and ranks what it finds worst
first, with the remediation for each.

```bash
entrascope doctor                          # can entrascope see what it needs
entrascope investigate                     # what is wrong in this tenant
entrascope investigate --severity error    # only what is already broken
entrascope investigate my-api              # narrow to one application
entrascope investigate my-api --full       # and show the evidence behind it
```

The argument to `investigate` is an application id, an object id or part of a
display name, whichever the error message gave you. The same value works as
`--app` on every other command. Findings are ranked **error** for something
already broken, **warning** for something that will break, and **note** for the
context that explains a result.

### Looking at one thing at a time

```bash
entrascope discover applications --expiring          # credentials about to expire
entrascope discover applications --type single-page-application
entrascope discover enterprise-apps --type managed-identity
entrascope discover applications --app my-api --output json

entrascope logs audit --failures-only                # failed directory changes
entrascope logs audit --app my-api
entrascope logs signins --kind service-principal --failures-only
entrascope logs signins --app my-api --hours 6
entrascope logs graph-activity --workspace <workspace-id>
entrascope logs kinds                                # which sign in kinds exist
entrascope logs audit --pick                         # number the lines and open one

entrascope discover gallery saml                     # what can be added ready made

entrascope errors explain AADSTS7000215
entrascope errors explain "AADSTS50011: The redirect URI does not match"
entrascope errors search consent
entrascope errors list
```

`discover apps` and `discover sps` still work as short forms.

### Reading the same data two ways

Audit events and sign ins can be answered by Microsoft Graph or by Azure
Monitor, and both return the same fields.

```bash
entrascope logs audit --route graph                        # any tenant
entrascope logs audit --route monitor --workspace <id>     # longer retention
```

The Graph route needs only the right permission. The Monitor route needs a
diagnostic setting and the Log Analytics Reader role, and gives longer
retention. Microsoft Graph activity exists only through Azure Monitor. Sign in
logs of any kind need an Entra ID P1 or P2 licence; audit logs do not.

### Output

Four formats, each for a different reader.

| Format | For |
| --- | --- |
| `table` | reading at a terminal. Aligned columns, no box drawing, colour where colour means something |
| `plain` | grep, awk, a spreadsheet, or pasting into a ticket. Tab separated, every field, nothing truncated |
| `json` | a machine. The same bytes an MCP tool returns |
| `yaml` | a machine, read by a person |

A table shows the columns worth reading and says so. Everything else is in
`--output plain`. `json` and `yaml` are quiet, so the output can be piped
straight into another tool. Timestamps are shown to a hundredth of a second
with the zone named, in UTC by default, or `--timezone local` for the machine's
own zone.

### Identity

`--auth` chooses it: `file`, `env`, `azure-cli` or `default`. Without it the
credential file is tried and then the Azure CLI session, so `az login` and then
`entrascope doctor` works with nothing else set up. The credential file wins
when it is present, so an unattended run behaves the same whatever else is on
the machine.

`errors explain`, `errors list` and `errors search` need no credentials at all,
because the mapping is configuration.

Every option works on either side of the subcommand: `entrascope --auth
azure-cli logs audit` and `entrascope logs audit --auth azure-cli` are the same
command.

## As an MCP server

```bash
entrascope serve stdio
```

Register it with an assistant that speaks the Model Context Protocol. stdio has
no OAuth, so credentials come from the environment or the credential file
exactly as they do for every other command, and the server runs with your
privileges. Every tool reads. None of them changes the directory.

The tool surface mirrors the commands: `doctor`, `discover_applications`,
`discover_service_principals`, `audit_events`, `sign_ins`, `graph_activity`,
`explain_error`, `list_error_codes` and `sign_in_kinds`. A tool result and the
corresponding `--output json` payload are the same bytes, which a test
enforces.

### As a remote server

```bash
entrascope serve http --host 0.0.0.0 --port 8000
```

An OAuth 2.1 protected resource validating Entra issued bearer tokens.
Terminate TLS at a reverse proxy and set `ENTRASCOPE_BASE_URL` to the canonical
https URI, which appears in the protected resource metadata and which clients
bind their tokens to. Set `ENTRASCOPE_TENANT_ID` and `ENTRASCOPE_CLIENT_ID` for
the application registration this server presents.

The audience must equal the application id URI, a token issued for anything
else is refused, and the caller's token is never forwarded to Microsoft Graph:
Graph is called with the server's own credentials, because the data is tenant
scoped rather than caller scoped.

A container image is built from the `Dockerfile`, running as a non root user on
`python:3.14-slim`.

## Corporate networks

entrascope honours a forward web proxy from `HTTPS_PROXY`, `HTTP_PROXY`,
`ALL_PROXY` and `NO_PROXY`, and verifies TLS against a private certificate
authority named in `ENTRASCOPE_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`,
`SSL_CERT_FILE`, `CURL_CA_BUNDLE` or the `SSL_CERT_DIR` directory. The same
trust reaches the token endpoint and Azure Monitor. Run `entrascope doctor` to
see exactly which proxy and which certificate authority are in force.

## Documentation

Steering documents live in [docs/steering](docs/steering):
[product](docs/steering/product.md),
[technology stack](docs/steering/tech-stack.md),
[repository structure](docs/steering/repo-structure.md),
[coding standards](docs/steering/coding-standards.md),
[configuration](docs/steering/configuration.md),
[credentials and security](docs/steering/credentials-and-security.md),
[Graph and Monitor](docs/steering/graph-and-monitor.md),
[MCP server](docs/steering/mcp-server.md),
[testing strategy](docs/steering/testing-strategy.md),
[release and publishing](docs/steering/release-and-publishing.md) and the
[phased task plan](docs/steering/tasks.md).

## Contributing

One change is one pull request, and every check must pass before it merges. The
gate is `ruff check`, `ruff format --check`, `mypy --strict src` and `pytest`,
plus five structural guards: no endpoint or table name written into code, no
class without a framework contract comment, no secret in any output, one HTTP
stack, one logger.

```bash
python3.14 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check src/ tests/ && .venv/bin/mypy --strict src && .venv/bin/pytest
```

The rules the code follows, and why, are in
[docs/steering](docs/steering). Read
[coding-standards.md](docs/steering/coding-standards.md) first.

## Security

Reporting a vulnerability, what entrascope does with credentials, and the rules
the remote server holds to: [SECURITY.md](SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE).
