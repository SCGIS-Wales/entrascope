# Changelog

All notable changes to this project are documented in this file.

The format follows Keep a Changelog, and this project adheres to semantic
versioning.

## [Unreleased]

### Changed
- The Azure CLI session resolves automatically. Somebody who ran az login no
  longer has to name a source. The credential file still wins when present, so
  an unattended run is unchanged, and the environment variables and the full
  azure-identity chain stay off because either can pick up an identity nobody
  intended.
- Every global option works on either side of the subcommand.
- Output reworked for reading and for copying. Tables lost their box drawing,
  which could not be pasted and read worse the longer they got, and gained
  colour on the values that carry a severity or an outcome, adaptive width, a
  count on the end, and a readable subset of columns rather than every field
  squeezed into none. A new plain format is tab separated, complete and
  untruncated, for grep, a spreadsheet or a ticket. A table written to a pipe
  is no longer truncated to a guessed eighty columns.
- Timestamps show a hundredth of a second and name their zone, in UTC by
  default or the machine's own with --timezone local. Guest accounts are shown
  as the part that names the person.
- Audit events say what kind of object was changed, in this tool's own words,
  and carry its identifier.
- A cell holding a list of objects is summarised by count and state rather than
  filling the line with JSON.
- The default log listing is 25 rows rather than 100.
- logs kinds describes what each kind covers and what it needs, rather than
  showing the OData filter, and can be given one kind to describe.

### Added
- entrascope whoami: the tenant by name and identifier, the tenants this
  identity can reach, the permissions the token actually carries, the directory
  roles held, the administrative units that bound them, and the conditional
  access policies in force.
- entrascope inspect: one application in full as YAML, coloured at a terminal,
  covering the registration and the enterprise application together, the scopes
  exposed, the roles defined, what was asked for against what was consented,
  every URL, the credentials and their expiry, and the single sign on
  configuration. With no argument it offers a chooser that moves with the arrow
  keys or with j and k and searches with a slash, as in vi.
- entrascope discover gallery: search the applications that can be added ready
  made, and which single sign on modes each supports.
- A pick option on the log commands, which numbers the lines, asks which to
  open, and shows that record whole with its explanation and a link into the
  portal.
- Names in a listing link into the Azure portal, and documentation links are
  clickable, in a terminal that understands hyperlinks.
- Twenty seven more error codes, covering the OAuth 2.0 and OpenID Connect
  failures and the SAML ones, and the entitlement exception a tenant without a
  premium licence meets when configuring single sign on.
- The Model Context Protocol surface gained tools for whoami, inspect and the
  gallery, and a test now walks the command line and asserts that every command
  has a tool and that the tools take the arguments the commands take.

### Fixed
- The servers no longer fail with a stack trace when their dependency is
  missing or half installed. fastmcp moved to an optional extra, so a command
  line install does not carry it, and a broken one is reported as a sentence
  with the command that repairs it.
- The doctor no longer reports a Global Administrator as unauthorised. A
  delegated token carrying Directory.AccessAsUser.All reads whatever the person
  can read, and their directory roles decide that.
- The Azure Monitor route explains what it needs and what to use instead, and a
  workspace can be set once in configuration.
- An audit listing shows the reason whenever something failed, and says how to
  look closer.
- Control C now stops the tool. A threaded fan out abandons its queue instead
  of draining it, and the process leaves at once rather than joining every
  worker and printing a second traceback over the first.
- A subcommand typed at the top level says where it lives and prints its help,
  rather than only reporting that no such command exists.
- Options given with no command show the help rather than reporting a missing
  command.
- The doctor reports the credential file only when the credential file is the
  source that answered, rather than telling somebody who signed in with the
  Azure CLI off for not having one.


## [0.1.0]

### Added
- Repository scaffold: package layout, configuration files, steering
  documents and the continuous integration pipeline.
- Configuration for endpoints, Log Analytics tables, retry and concurrency,
  field projections, logging and redaction, error code remediation and
  capability prerequisites.
- KQL templates for sign in failures, application management audit events and
  Microsoft Graph activity.
- Five structural guards enforced in continuous integration: no hardcoded
  endpoints, no classes without a framework contract comment, no secret in
  output, one HTTP stack and one logger.
- Configuration loader validating every file against a schema, with a cached
  accessor, KQL template loading and parameter substitution, and a search order
  that prefers an explicit directory, then the environment variable, then the
  configuration packaged inside the wheel, then the repository directory.
- The common logger: one factory, redaction applied as a handler filter, a
  correlation id carried in a context variable, standard context fields naming
  the authentication source and tenant, and both a human and a JSON line
  format selected per surface.
- Redaction by configured key, by pattern for bearer tokens and JSON web
  tokens, and by literal once the secret is known.
- The credential contract: the file at ~/.entra/provisioner-credentials.json
  with mode 0600 inside a directory with mode 0700, refusing to run otherwise
  and naming the exact chmod without revealing the secret.
- Four authentication sources: the credential file, the ARM environment
  variables, the Azure CLI session and DefaultAzureCredential. Only the file
  source resolves automatically by default, and naming any source with --auth
  selects it regardless.
- The HTTP transport: one session factory, retry and backoff expressed as a
  urllib3 policy mounted on the adapter, timeouts and pool sizes from
  configuration, an access log line per call, and one structured error carrying
  the status, code, message, correlation id and request id, recognising the
  Microsoft Graph, Azure Resource Manager and token endpoint error shapes.
- Threaded fan out over independent sessions, ordered results, worker count
  from configuration.
- Microsoft Graph calls with every endpoint read from configuration, next link
  paging bounded by a page ceiling, OData query parameters, single object and
  collection reads, and a token provider that caches inside a closure and
  renews before expiry.
- Azure Monitor log queries rendered from KQL templates by named parameter,
  returning an immutable result that keeps partial data along with the reason
  it was partial.
- Discovery of application registrations and enterprise applications, with
  projection driven entirely by the field mappings in configuration: sign in
  audience and a readable description of it, redirect URIs kept apart by
  platform, requested permissions with delegated and application entries kept
  apart, granted permissions from consent grants and role assignments, owners,
  credentials with their expiry state, federated identity credentials, SAML
  configuration with the signing certificate, and the assignment requirement.
- Classification covering confidential clients, public clients, native and
  mobile clients, single page applications, workload identity federation,
  gallery and non gallery SAML enterprise applications, managed identities and
  legacy applications, driven by values in configuration rather than literals.
- Synthetic Graph fixtures, with a test asserting that no identifier in them
  could be a real tenant identifier, because the repository is public.
- Log interrogation of directory audits, the four sign in kinds, provisioning
  and Microsoft Graph activity, through both the Graph reporting API and Azure
  Monitor, with both routes projecting the same objects. Sign in event type
  filters, diagnostic categories and KQL template names are all configuration.
- Microsoft Graph activity is marked as having no Graph route, and asking for
  it that way returns the reason and the diagnostic category it needs.
- Forward web proxy support from the conventional environment variables, and
  TLS verification against a certificate authority bundle or directory named in
  ENTRASCOPE_CA_BUNDLE, REQUESTS_CA_BUNDLE, SSL_CERT_FILE, CURL_CA_BUNDLE or
  SSL_CERT_DIR. The same trust reaches azure-identity and azure-monitor-query.
  Verification is never disabled by a path that does not exist.
- One renderer shared by every surface, with table, JSON and YAML output, one
  exit code map, and redaction applied to everything that leaves the process.
- Capability detection: permissions read from the live token rather than a
  table, licence tier read from the subscribed service plans, and the enabled
  diagnostic categories read from the Entra diagnostic settings.
- The doctor command, reporting the network path, the credential file, the
  identity in use, what the token actually grants, the licence tier, every
  diagnostic category and every configured capability, each failure carrying
  its remediation and a documentation link. Authorisation is checked
  differently for a delegated session, where directory roles apply rather than
  application permissions.
- Command line foundation: the --auth, --output, --config-dir and --verbose
  options, a correlation id per invocation, and deliberate errors rendered as a
  message and an exit code rather than a stack trace.
- Commands: discover apps and discover sps with filtering by type and by
  expiring credential, logs audit, logs signins and logs graph-activity each
  choosing between the Graph route and the Azure Monitor route, logs kinds, and
  errors explain, errors list and errors search which need no credentials.
- entrascope investigate, which gathers credentials, directory changes and
  sign in failures, applies rules from configuration and ranks what it finds
  worst first with the remediation for each. Tenant wide with no argument, or
  narrowed to one application by id, object id or part of a display name.
  Findings are errors, warnings or notes, and --severity filters them.
- Microsoft first party enterprise applications are excluded by default,
  because a tenant carries hundreds and they are Microsoft's to manage.
- One application selector, --app, meaning the same thing on every command.
- The command line answers with its help when given nothing, every group lists
  its commands, every group carries worked examples, and a command missing a
  required argument shows what it needs rather than an error.
- discover apps and discover sps are now discover applications and discover
  enterprise-apps, with the short forms retained as aliases.
- Machine readable output is quiet. Progress lines are suppressed under
  --output json and --output yaml so the output can be piped directly.
- Continuous integration actions moved to the majors that run on Node 24.
- The local MCP server, over stdio, exposing nine read only tools built from
  the same functions the commands call. A tool result and the corresponding
  --output json payload are the same bytes, which a test enforces.
- The remote MCP server over Streamable HTTP, an OAuth 2.1 protected resource
  validating Entra issued tokens, with protected resource metadata per RFC
  9728, a health endpoint, CORS closed until an origin is named, per client
  rate limiting, and a multi stage container image running as a non root user.
- The audience is narrowed to the application id URI, which the steering rule
  requires and which a public FastMCP parameter and attribute provide, so no
  private attribute is touched.
- The negotiated protocol revision is pinned in configuration, checked at
  startup and asserted in a test.
- entrascope serve http runs the remote server. Every line the container emits
  is a JSON line from the common logger, because the web server is told to
  install no logging configuration of its own.
- entrascope serve stdio runs the local server. Standard output carries the
  protocol alone, with logging and the banner on standard error, which a
  subprocess test enforces.
- Error interpretation from configuration: exact and case insensitive lookup, a
  code extracted from a longer message, the specific AADSTS code preferred over
  a generic one such as invalid_client, and a configured default for anything
  unrecognised so that an unknown code still yields a link and a next step.
- Release automation, gated by repository variables so that a merge to main
  publishes nothing until the project is ready: auto-tag computes the next
  patch version, rewrites it in the packaging and the package, commits, tags,
  and hands the distribution to the publish jobs in the same run. Publishing
  uses PyPI Trusted Publishing with no tokens, retries three times with backoff
  because the transparency log intermittently fails while generating
  attestations, and a GitHub release is created from the same artefact.
- SECURITY.md, stating what entrascope does with credentials, how to report a
  vulnerability, and the three rules the remote server holds to.
- A release can be started by hand as well as by a merge, optionally naming the
  version, which is how a minor release is cut and how a re-run after a
  transient publishing failure is done.

[0.1.0]: https://github.com/SCGIS-Wales/entrascope/releases/tag/v0.1.0
