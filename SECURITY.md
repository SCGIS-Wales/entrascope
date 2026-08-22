# Security

## Reporting a vulnerability

Report a suspected vulnerability privately through GitHub security advisories on
[SCGIS-Wales/entrascope](https://github.com/SCGIS-Wales/entrascope/security/advisories/new).
Please do not open a public issue for a vulnerability.

Include what you did, what happened, and what you expected. A proof of concept
helps. You will get an acknowledgement within a few working days.

## What entrascope does with your credentials

- It reads. It never writes to the directory, never grants consent, never
  rotates a credential and never changes a diagnostic setting. It tells you the
  command that would.
- The client secret is never logged and never printed. Redaction is a logging
  filter installed once, so it applies to every record from every module rather
  than depending on each call site remembering. A test drives every command and
  every tool with a sentinel secret and asserts it appears in no output stream
  and no log record.
- The credential file must be mode 0600 inside a directory of mode 0700.
  entrascope refuses to run otherwise and prints the exact chmod, without
  revealing the secret.
- Tokens are never written to disk. The Azure CLI source holds no secret at all.

## Network and certificate trust

Forward web proxies are honoured from the conventional environment variables.
TLS is verified against a certificate authority bundle or directory named in
`ENTRASCOPE_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`
or `SSL_CERT_DIR`. A variable pointing at a path that does not exist falls
through to the bundle that requests ships: **verification is never silently
disabled by a bad path**. Turning it off is a deliberate change to `verify_tls`
in configuration, and `entrascope doctor` then reports it as a failed check.

## The remote server

The remote MCP server is an OAuth 2.1 protected resource. Three rules hold, and
each is covered by a test:

1. It never accepts a token that was not issued for it.
2. The audience claim must equal the configured application id URI.
3. The caller's token is never forwarded to Microsoft Graph. Graph is called
   with the server's own credentials, because the data is tenant scoped rather
   than caller scoped.

Terminate TLS at a reverse proxy. The container binds inside itself, runs as a
non root user and is built on `python:3.14-slim`.

## The local server

A stdio server has no OAuth and runs with the privileges of whoever launched
it. Consent to it explicitly before installing or running it. It reads, it
validates every tool input, and no tool result carries a secret.

## Supply chain

- Dependencies are audited on every pull request with `pip-audit`, and a
  CycloneDX software bill of materials is published as a build artifact.
- CodeQL analyses the Python and the workflows weekly.
- Dependabot proposes updates weekly for Python packages, actions and the
  container base image.
- Releases are published to PyPI with Trusted Publishing over OpenID Connect.
  There are no long lived API tokens anywhere in this repository, and every
  release carries attestations.

## Permissions entrascope asks for

Four Microsoft Graph application permissions, all read only:
`Application.Read.All`, `AuditLog.Read.All`, `Directory.Read.All` and
`Policy.Read.All`. `AppRoleAssignment.ReadWrite.All` is deliberately excluded,
because it lets an application grant privileges to itself.

Under a delegated identity such as an Azure CLI session, directory roles apply
instead, and Global Reader is sufficient.
