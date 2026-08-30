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

- **Diagnosis.** `investigate` gathers credentials, directory changes and sign
  in failures, applies a set of rules and ranks what it finds worst first, with
  the remediation for each. Tenant wide, or narrowed to one application.
- **Inspection.** `inspect` shows one application in full: the registration and
  the enterprise application together, what it exposes, what it asked for
  against what was consented, every URL, and its credentials.
- **Identity.** `whoami` says which tenant and identity you are querying as,
  what the token actually grants, the directory roles held and the conditional
  access policies in force.
- **Readiness.** `doctor` reports the network path, the credential file, the
  licence tier and every diagnostic category, each failure with its
  remediation.
- **Discovery.** Enumerate application registrations and enterprise
  applications of every type, and project sign in audience, redirect URIs,
  requested and granted permissions, owners, credentials and their expiry,
  federated identity credentials, SAML configuration and the assignment
  requirement.
- **Log interrogation.** Read Entra audit logs, interactive and non interactive
  user sign ins, service principal and managed identity sign ins, Microsoft
  Graph activity and provisioning logs.
- **Error explanation.** Map AADSTS and Microsoft Graph error codes to meaning,
  likely cause and remediation, with no credentials needed.

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

On a Python that Homebrew or your distribution manages, `pip` will refuse, and
it is right to. Use one of these instead:

```bash
pipx install entrascope          # or
uv tool install entrascope       # or
python3 -m venv ~/.venvs/entrascope && ~/.venvs/entrascope/bin/pip install entrascope
```

### Staying current

entrascope checks for a newer version at most once a day, never blocking a
command, and says one line on standard error when there is one. Set
`ENTRASCOPE_NO_UPDATE_CHECK=1` to switch it off.

```bash
entrascope upgrade --check    # what is running, what is newest, what would upgrade it
entrascope upgrade            # upgrade the way this copy was installed
```

It works out whether it is in a virtual environment, under pipx, under uv, or
in a Python something else manages, and uses the right command through the
running interpreter rather than whichever `pip` is on the path. On a managed
Python it refuses and shows the safe routes, with
`--break-system-packages` there if you decide otherwise.

From a clone, for development:

```bash
python3.14 -m venv .venv && .venv/bin/pip install -e ".[dev]"
```

## Authentication

The quickest route needs nothing but an Azure CLI session. No flag, because
that session is tried automatically when there is no credential file:

```bash
az login
entrascope doctor
```

For unattended use, place client credentials at
`~/.entra/provisioner-credentials.json` with the keys `ClientID`, `TenantID`
and then either `Secret` or `CertificatePath`. The file must be mode 0600
inside a directory of mode 0700, and entrascope refuses to run otherwise.

One file per tenant is ordinary, so the file can be named:

```bash
entrascope --credentials provisioner-credentials-stage.json doctor
export ENTRASCOPE_CREDENTIAL_FILE=provisioner-credentials-stage.json
```

A bare name is a file inside `~/.entra`; a path is used as given. Naming one
means the file source, so `--auth` is not needed as well.

### Where the credentials live

The directory and the file name are settings rather than facts, so a machine
that keeps them somewhere else needs no environment variable on every command:

```bash
entrascope config credentials                            what is in force now
entrascope config credentials --directory ~/.entra-prod  keep them elsewhere
entrascope config credentials --file staging.json        another tenant
entrascope config credentials --choose                   pick from what is there
entrascope config credentials --forget                   back to the defaults
```

Anything set there is written to your own configuration directory, layered over
the shipped defaults, and is never touched when entrascope is upgraded.

When the expected file is absent and other credential files are sitting beside
it, entrascope offers them rather than repeating the name it wanted, and
remembers the one you pick so that the next run does not ask. With no terminal
it does not ask at all: an unattended run fails with the message it always had.

### A certificate instead of a secret

Entra accepts either for an application, and a certificate is the better of the
two: it is never transmitted, so it cannot be read out of a log or a proxy.
Point the credential file at one and leave `Secret` out:

```json
{
  "ClientID": "...",
  "TenantID": "...",
  "CertificatePath": "app.pem"
}
```

A bare name is a file beside the credential file; a path is used as given. PEM
and PKCS12 both work, `CertificatePassword` unlocks a PKCS12 that has one, and
`SendCertificateChain` turns on subject name and issuer authentication. The
certificate must be mode 0600 as well, because the private key in it is exactly
as sensitive as a secret, and entrascope refuses to run rather than use one
anybody else can read.

`ARM_CLIENT_CERTIFICATE_PATH` and `ARM_CLIENT_CERTIFICATE_PASSWORD` do the same
through the environment, under the names the Azure provider for Terraform
already uses. `entrascope config credentials --certificate app.pem` sets one
for every credential file that names none of its own.

### What it says it is using

Every run ends with one line in red naming the credential kind in force and the
files it came from:

```
credentials: client certificate through file  file /home/ada/.entra/prod.json  certificate /home/ada/.entra/app.pem
```

It goes to standard error, so redirecting output to a file leaves the file
holding the answer alone. It is never printed for `--output json`, `yaml` or
`plain`, never without a terminal, and `NO_COLOR` drops the colour. Switch it
off entirely under `banner` in `credentials.yaml`. Running a diagnosis against
the wrong tenant is the most expensive mistake this tool can help you make, and
it is the one mistake nothing else here reports.

A credential file that is present but unsafe stops the command rather than
being worked around, and prints the exact `chmod`. Leaving it readable by
others while quietly authenticating some other way is not a kindness. A file
that is simply absent is passed over, and any later failure says which identity
answered and what was passed over to reach it.

## Using it

Run `entrascope` with no arguments and it tells you what it can do, then offers
the commands to choose from. Every group does the same, and every command
carries its own help and worked examples. Piped or in a script, all of them
print their help and exit, so nothing that automates this changes.

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

### Looking at applications

Listing applications and reading one of them are the same question asked at two
depths, so they are one command.

```bash
entrascope inspect                 # choose from a list, with / to search
entrascope inspect saml2           # by name
entrascope inspect d6bdb5c4-1722-4c63-930f-fa264d4778bc
entrascope inspect --type managed-identity
entrascope inspect applications    # the whole list as a table
entrascope inspect enterprise-apps
```

Shows the registration and the enterprise application together, as YAML,
coloured at a terminal and plain in a pipe: the scopes it exposes, the roles it
defines, what it asked for against what was actually consented, who may use it,
every URL it is registered with, its credentials and their expiry, and its
single sign on configuration.

#### Consent, and what is missing from it

The `permissions.consent` section answers the question a permission failure
usually turns on. Each permission the registration asks for is named rather
than left as an identifier, and carries whether only an administrator may
consent to it and whether anybody did.

Three lists say what is wrong, and they say different things:

- `without_admin_consent` names every permission that needs an administrator
  and does not have one. Each of these is refused for everybody, and
  `admin_consent_complete` is false while any of them remains.
- `user_consented_only` names the delegated permissions one person consented to
  for themselves rather than for the tenant. These work for that person and are
  refused for everybody else, which is what a failure only one engineer cannot
  reproduce looks like.
- `not_consented` names everything asked for and never granted at all,
  including the permissions a user may consent to on their own.

An investigation reports the same two conditions as findings, an error for the
first and a warning for the second, so a tenant wide sweep names every
application waiting on consent.

#### Who may use it

The `access` section is the other half of authorisation, and consent says
nothing about it. It lists the security groups, the users and the applications
assigned to the enterprise application, each with the role it was assigned. A
group is the usual answer and was previously invisible.

Where `assignment_required` is true, an identity that is not assigned is
refused however much has been consented.

`access.member_of` lists the groups, directory roles and administrative units
the application's own identity belongs to. Access held that way is granted to
the group rather than to the application, so nothing on the application records
it, and a dynamic group is marked as such because its membership changes
without anybody assigning anything.

#### On behalf of, SAML and the policies that rewrite a token

`exposes.pre_authorized_applications` names each client allowed to ask for this
resource's scopes without a consent prompt, and names the scopes it may ask
for. An on behalf of chain runs with nobody present to answer a prompt, so a
client pre authorised for the wrong scope fails exactly like one that is not
pre authorised at all, and only the scope names tell the two apart.

`single_sign_on` covers what a registration does not show. For SAML that is
which of several certificates actually signs, whether any address is registered
to be warned before it expires, where the service provider begins sign in, the
relay state and the token encryption key. A signing certificate nobody is
warned about ends single sign on for everybody at once, on a date nobody is
watching, so it is a finding of its own.

`single_sign_on.policies` lists the claims mapping, home realm discovery and
token lifetime policies assigned to the enterprise application. Each rewrites a
token without the registration recording that it does, which is why a token
compared against the registration that produced it can disagree with it. A
claims mapping policy assigned to an application that does not accept mapped
claims is ignored rather than refused, so it looks exactly like a policy that
does not work; that pairing is reported as an error.

`provisioning.isFallbackPublicClient` is the setting behind two failures that
read as credential problems. A confidential client with it set presents its
secret and is refused with AADSTS700025. A native client without it is refused
with AADSTS7000218 for not sending a secret it cannot hold. Both are findings.

With no argument and a terminal to draw on, it offers the list. Move with the
arrow keys or with j and k, and the arrows keep moving while a search is being
typed. Search with `/` as in vi, `s` cycles the order between name, name
reversed, newest and oldest, page up and page down move a screen at a time,
enter opens, escape goes back.

Colour carries meaning rather than decoration: an application whose credential
has expired is red, one expiring soon amber, an OAuth or OpenID Connect
application orange, a SAML application violet. The palette is configuration,
under `fields.display.chooser`, and it is chosen to be read on a dark terminal.

After showing an application it offers what to do next: back to the list, save
that application to a YAML file, or leave. Looking at one application is rarely
the whole question.

The list holds names and identifiers only, so it appears at once on a tenant of
several hundred applications; everything else is read for the one that is
chosen. Microsoft first party applications and the managed identities Azure
creates for its own resources are kept out of it, with a count of what was
hidden. `--all` includes them.

Any command group given no subcommand does the same: it prints its help and
then offers its commands, asking for whatever the chosen one cannot do without.
The menu comes back after each command rather than returning you to the shell,
waiting for a keystroke first so that what the command said stays on the screen
to be read and scrolled through. A command that fails says so and the menu
returns, as does one that ends with a non-zero exit code, and every menu offers
the way out rather than leaving you to guess at it. A prompt for an argument takes
a blank answer as going back. Piped or in a script, the help is printed and
nothing is offered, exactly as before.

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
entrascope investigate --follow            # watch it live, newest first
```

`--follow` opens a live view rather than a report. The audit log and the sign in
logs stream newest at the top and refresh on their own, coloured by what each
line means: errors red, warnings amber, everything else quiet. Type `/` and
some words to narrow it, `f` to cycle the severity floor, `p` to pause while
you read a line, `r` to ask again now, `q` or escape to go back to the menu.
Nothing in it leaves the tool.

Managed identities are left out: Azure signs them in constantly and none of it
is anybody's authentication problem. `--kind managed-identity` watches them
anyway.

The same failure happening forty times is one line saying forty, timestamped at
the most recent, rather than forty lines saying the same thing. Every line
carries the day, the month, the year, the time to the second and the zone it is
shown in, which is the machine's own zone unless `--timezone utc` says
otherwise. The tool's own log lines appear in the same list, which is where the
reason for an empty screen belongs.

Findings name both the display name and the application id, because an error
message quotes the identifier and never the name, and two applications in a
tenant may share a name.

The argument to `investigate` is an application id, an object id or part of a
display name, whichever the error message gave you. The same value works as
`--app` on every other command. Findings are ranked **error** for something
already broken, **warning** for something that will break, and **note** for the
context that explains a result.

### Signing in for real

Everything above reads what the tenant has recorded. `attempt` runs the flow,
because a registration that looks correct and a sign in that works are
different claims, and only the second one matters to somebody who cannot get
in.

```bash
entrascope attempt                                   # choose from the ones that can
entrascope attempt my-desktop-app                    # one, by name
entrascope attempt my-api --scope User.Read --scope Mail.Read
entrascope attempt my-web-app --secret               # a confidential client
entrascope attempt my-app --no-browser               # over SSH, or with no browser
```

It runs an OAuth 2.0 authorization code flow with PKCE, which is the shape
[RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html) specifies for a native
application and a command line tool is one: your own browser rather than an
embedded one, a redirect back to the loopback address, a high entropy `state`,
and a proof key so that a code intercepted on the loopback interface cannot be
spent by anything else.

What happens, in order:

1. The applications that can be signed into are listed, which means the ones
   with a redirect URI that comes back to this machine. One is chosen, or named
   as an argument.
2. A listener is bound to the loopback address alone, on the port the redirect
   URI names, or a free one from `listener.port_range` when it names none. 80,
   443, 8000, 8080 and 8443 are refused outright, because something else is
   almost always serving there.
3. Your browser opens at the Microsoft sign in page. You authenticate there and
   nowhere else: entrascope never sees the password, and never asks for it.
4. Entra redirects back with a code. The `state` is checked before the code is
   read, the code is exchanged for a token, and the listener is closed.
5. The report says what the token **actually** carries: the scopes granted
   against the scopes asked for, the roles, the audience, the issuer, whether a
   refresh token came back, and who the token says you are.

The last of those is the point. A scope asked for and not granted still gives a
successful sign in, and only fails later when something calls with the token,
which is why a broken integration so often reads as working.

**What the application needs first.** A redirect URI that comes back to this
machine, under the mobile and desktop platform, which needs no secret. Entra
permits plain HTTP for the loopback address and for nothing else. Register the
IP literal rather than `localhost`: a renamed network interface or a firewall
that treats the name differently breaks the name and never breaks the address.

Adding a redirect URI is a change to the registration, and entrascope only
reads, so it will not make one. Where it is missing, the exact address to
register and the `az` command that registers it are printed.

**Secrets.** None is needed. PKCE replaces the secret, which is what it was
designed for. `--secret` prompts for one, without echoing it, only for an
application whose redirect URI is registered under the *web* platform, which
Entra refuses to let a public client use. A secret given that way lives in one
local variable for the length of one token request: it is never written to a
file, never taken from the command line where a shell history would keep it,
and it is added to the redaction filter the moment it is known, so it cannot
reach a log even by accident.

**Teardown.** The listener answers exactly one redirect and is closed on every
path out, including a timeout and a control C. Nothing is left listening and
nothing is left in the directory, because nothing was put there.

**When it goes wrong.** Run with `--verbose` for the whole trace: which
redirect URI was chosen and why, the port bound, the address the browser was
sent to, what arrived on the redirect and what the token endpoint answered. An
error from Entra carries an AADSTS code, and `attempt` explains it with the
same mapping `entrascope errors explain` uses. The code, the verifier and any
secret are redacted from all of it.

`attempt` is deliberately absent from the MCP tool surface. It opens a browser
and waits for a person to sign in to it, and there is nobody at a keyboard
there.

### Looking at one thing at a time

```bash
entrascope inspect applications --expiring           # credentials about to expire
entrascope inspect enterprise-apps --expiring        # including SAML signing certificates
entrascope inspect applications --type single-page-application
entrascope inspect enterprise-apps --type managed-identity
entrascope inspect applications --app my-api --output json

entrascope logs audit --failures-only                # failed directory changes
entrascope logs audit --app my-api
entrascope logs signins --kind service-principal --failures-only
entrascope logs signins --app my-api --hours 6
entrascope logs graph-activity --workspace <workspace-id>
entrascope logs kinds                                # which sign in kinds exist
entrascope logs categories                           # which audit categories exist
entrascope logs audit --category all --hours 6       # every category, last six hours
entrascope logs audit --pick                         # number the lines and open one

entrascope inspect gallery saml                      # what can be added ready made

entrascope errors explain AADSTS7000215
entrascope errors explain "AADSTS50011: The redirect URI does not match"
entrascope errors search consent
entrascope errors list
```

`inspect apps` and `inspect sps` are short forms, and `discover` is the name
`inspect` used to have, which still works.

### The types an application is classified as

`--type` takes one of these. The registration decides the first six; the last
four are what a service principal itself determines.

| Type | What it means |
| --- | --- |
| `confidential-client` | holds a secret or a certificate |
| `web-client` | a web redirect URI and no credential |
| `single-page-application` | authorization code with a proof key, no secret |
| `native-or-mobile` | a public client redirect URI and no credential |
| `public-client` | nothing registered that says how it authenticates |
| `api-or-resource` | exposes an API and signs nobody in |
| `workload-identity-federation` | a federated credential rather than a secret |
| `saml-gallery` | SAML single sign on, from the gallery |
| `saml-non-gallery` | SAML single sign on, configured by hand |
| `managed-identity` | created by Azure alongside a resource |
| `enterprise-application` | a service principal whose client type is decided by its registration |
| `legacy` | predates the current application model |

### Reading the same data two ways

Audit events and sign ins can be answered by Microsoft Graph or by Azure
Monitor, and both return the same fields.

```bash
entrascope logs audit --route graph                        # any tenant
entrascope logs audit --route monitor --workspace <id>     # longer retention
```

The route decides where an answer comes from, not which questions may be asked.
Both take the same `--app`, `--hours`, `--limit` and `--category`, and both
narrow at the service rather than after the rows arrive, so a lookback is a
lookback and not a suggestion. Each sign in kind is exported to a table of its
own, and the monitor route reads the table belonging to the kind asked for.

The Graph route needs only the right permission. The Monitor route needs a
diagnostic setting and the Log Analytics Reader role, and gives longer
retention. Microsoft Graph activity exists only through Azure Monitor. Sign in
logs of any kind need an Entra ID P1 or P2 licence; audit logs do not.

### Configuration

Every endpoint, table name, retry value, error code, vocabulary and
documentation link lives in configuration rather than in code.

```bash
entrascope config path                              # which directory is in force
entrascope config export                            # a copy to read, in Downloads
entrascope config export --use                      # put it where it takes effect
entrascope config export --only credentials.yaml    # or just the one file
entrascope config show                              # every setting in force
entrascope config show endpoints.yaml               # read one file
```

`config show` with nothing named is the configuration entrascope is actually
running with, as YAML, above the full paths it was read from and the
directories it searched in order. It is the answer to "which file do I edit".

`config export` with no destination writes to your downloads folder, where a
file is easy to find and open, and says so with the full path of everything it
wrote. That copy is for reading and does not take effect on its own.

`config export --use` writes to `~/.config/entrascope`, which is **outside the
package, so upgrading never touches it**, and which is used automatically. It
is **layered over the shipped defaults**: copy only the files you want to
change, and everything else comes from underneath, so a release that adds a
setting is picked up without you doing anything and a file you wrote two
releases ago keeps working.

Do not edit the copy inside `site-packages`. It is replaced every time
entrascope is upgraded, and `entrascope config path` will tell you if that is
the one being read.

`--config-dir` and `ENTRASCOPE_CONFIG_DIR` name a directory for one command or
one shell. A directory named that way is used **as it stands**, with no
layering, and is required rather than preferred, so a typo fails instead of
quietly falling back.

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

The tool surface mirrors the commands: `doctor`, `inspect`, `discover_applications`,
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
