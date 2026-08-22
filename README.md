# entrascope

Observability and diagnostics for Microsoft Entra ID and Azure Monitor, helping
engineers troubleshoot authentication and authorisation failures.

> Entra directory operations do not appear in the Azure subscription activity
> log. They are recorded in the Entra audit logs, under the category
> ApplicationManagement. entrascope reads them through Microsoft Graph and
> through Azure Monitor.

## Status

Under construction, phase by phase, against
[docs/steering/tasks.md](docs/steering/tasks.md). Phase 0 lays down the
scaffold, the configuration, the steering documents and the pipeline.

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

## Licence

MIT. See [LICENSE](LICENSE).
