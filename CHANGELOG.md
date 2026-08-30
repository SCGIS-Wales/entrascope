# Changelog

All notable changes to this project are documented in this file.

The format follows Keep a Changelog, and this project adheres to semantic
versioning.

## [Unreleased]

### Added
- Missing admin consent is reported rather than left to be inferred. Every
  permission a registration asks for is named, and carries whether only an
  administrator may consent to it and whether anybody did.
  `permissions.consent.without_admin_consent` names the ones refused for
  everybody, `user_consented_only` names the delegated permissions one person
  consented to for themselves alone, and `admin_consent_complete` says in one
  value whether anything is outstanding.
- An investigation reports the same two conditions as findings: an error for a
  permission needing admin consent and lacking it, a warning for one consented
  by an individual rather than for the tenant. A tenant wide sweep now names
  every application waiting on consent.
- `inspect` reports who may use an application, under `access`: the security
  groups, users and applications assigned to the enterprise application, each
  with the role it was assigned. The groups were previously invisible.
- `inspect` reports the groups, directory roles and administrative units the
  application's own identity belongs to, under `access.member_of`, with a
  dynamic group marked as such. Access held through a group is recorded on the
  group and nowhere on the application.
- `whoami` names the security groups an identity belongs to rather than only
  counting them.
- A note where an enterprise application requires assignment and every
  assignment is to a person rather than to a group, because access then has to
  be granted and revoked one person at a time.

### Changed
- The Graph vocabulary that was hardcoded in `src` moved into
  `config/fields.yaml`, as hard rule 3 requires: the `Scope` and `Role` markers,
  the `AllPrincipals` consent type, the `memberOf` OData types and the null app
  role identifier.

### Security
- A known client secret is now redacted as a literal as well as by pattern. The
  machinery for it was written and never wired up, so a secret echoed back by
  some library under a name we do not recognise would have been printed.
- A package index or proxy address carrying a user name and a password is
  redacted, as is a secret in a query string. The upgrade command echoes the
  address the installer was given, and it says so in a comment, but nothing
  redacted it.
- The pager will not follow an @odata.nextLink to another host. Every call
  carries a bearer token, and following a link off the host would hand the
  token to that host. Microsoft Graph would never send such a link, which is
  what makes the check free.
- A correlation id supplied by a caller of the remote server is accepted only
  when it is a plain identifier. It appears on every log line the request
  causes, so a newline in it would forge a line.
- A display name reaches the chooser and the live view with its control
  characters taken out. It is somebody else's text and both of them draw on a
  screen.
- A log line drawn by the live view is redacted again as it is drawn, rather
  than relying on the handler the view displaces.

### Fixed
- Granted application permissions were read from the wrong endpoint. `inspect`
  and the tenant sweep both read `appRoleAssignedTo`, which lists the users and
  groups assigned to an enterprise application, and reported those objects as
  the application permissions the application holds. What it holds is
  `appRoleAssignments`, and that is what is read now.
- Delegated consent was never read at all. The `oauth2PermissionGrants`
  endpoint was configured and called from nowhere, so the granted delegated
  permissions were always empty and the admin consent answer was decided
  without them.
- An inspection read the application registration twice, once to project it and
  once again whole. It is read once.
- `pluck` split `@odata.type` as though the dot were a path separator, so a key
  Microsoft Graph annotates a polymorphic collection with could not be mapped
  in configuration at all. A key present verbatim now wins over walking a path.
- A log record arriving from the polling thread could be dropped while the
  drawing thread emptied the queue, because reading a list and clearing it is
  two steps. Taking from a deque is one.
- A session could be closed while a worker thread was still using it when a
  fan out failed partway through. The pool is now waited for first, except on
  an interrupt, where stopping quickly is the point.
- A configuration export that hit a file already there stopped halfway,
  leaving a directory holding some of one release and some of another.
  Everything is checked before anything is written.
- Saving an application or an investigation no longer writes over a file of
  the same name. The next free number is used.
- A display name can no longer become a path when a report is saved.
- A row limit or a lookback reaching a KQL query is brought inside a ceiling.
  They are numbers, so nothing can be injected through them, but ten million
  rows is a way to hang a terminal rather than to read a log.
- The live view polls with a shorter timeout than a report uses, so leaving it
  cannot keep the process alive waiting on a call nobody will see.
- --follow with --output json said nothing and reported once. It now says why.
- The release cache lost the file addresses it had been given, so a cached
  answer could not name them.
- investigate --follow authenticated a second time to open the view. The token
  source outlives the session, so it is reused.
- A command run from a menu had its output wiped by the menu redrawing over it
  the moment it finished, which is why config show, config path, errors list
  and upgrade all appeared to do nothing. The menu now waits for a keystroke,
  so what a command said stays on the screen to be read and scrolled through.
- A command that ends with a non-zero exit code, which is how doctor reports a
  failed check and how investigate reports an error level finding, ended the
  whole session when it was run from a menu. The code is noted and the menu
  returns.
- The remote server refused to start when no canonical URI was set, which
  helped nobody trying it out on their own machine. It now assumes the loopback
  address, says out loud that it has, and says what to set in production. Both
  servers say that control C stops them.
- The live view left managed identities out. Azure signs them in constantly and
  none of it is anybody's authentication problem. --kind managed-identity
  watches them anyway.
- The live view said the same refusal once per source. One reason is now one
  line, naming the sources it stopped.

### Changed
- config export with no destination writes to the downloads folder, where a
  file is easy to find and open, and names every file it wrote. That copy is
  for reading. config export --use writes to the configuration directory, where
  entrascope reads it automatically, which is what the bare command used to do.

### Added
- upgrade names the files a release published, wheel first, so somebody whose
  Python is managed by something else, or who is behind a proxy that blocks the
  package index, has the address to hand. upgrade --check names them too,
  whether or not this copy is behind.
- The installer is run again when it fails, three times by default, because a
  package index that is briefly unreachable should cost a wait rather than an
  upgrade. An installer that will not start at all is reported at once, since
  no amount of waiting produces a program that is not there.
- investigate --follow watches a tenant rather than reporting on it once. The
  audit log and the sign in logs stream newest at the top, refreshing on their
  own, coloured by meaning: errors red, warnings amber, everything else quiet.
  Typing narrows by keyword, f cycles the severity floor, p pauses, r asks
  again now, and q or escape goes back to the menu rather than out of the tool.
  Interactively, the menu after an investigation offers it.
- The same failure happening forty times is one line saying forty, timestamped
  at the most recent, rather than forty lines saying the same thing.
- The tool's own log lines appear in the live view along with the events, which
  is where the reason for an empty screen belongs.

### Changed
- Timestamps are shown in the machine's own zone by default rather than in UTC,
  with the zone named as before. Somebody diagnosing a failure from twenty
  minutes ago should not have to do the arithmetic. --timezone utc is unchanged.
- Findings carry the application id beside the display name, and the moment the
  evidence was recorded where there is one. The occurrences column is gone: a
  count of one repeated down a column says nothing, and where a finding groups
  several events the detail says how many, in words.

### Fixed
- A refusal that entrascope raises on purpose, such as declining to upgrade
  into a Python that something else manages, was printed as a stack trace. It
  reads as a crash rather than as the considered answer it is, and it is now
  printed as the message it always carried.
- A log line written while the spinner was turning landed on top of it, which
  is how "⠸ Investigating...INFO discovered 383" came about. Log lines now go
  through the same console, which moves the spinner out of the way.
- A refusal the caller was going to report itself is no longer also shouted
  about by the transport. Reading five kinds of sign in from a tenant with no
  premium licence said the same thing six times.

### Changed
- discover and inspect were one question asked at two depths, so they are one
  command. `inspect applications`, `inspect enterprise-apps` and
  `inspect gallery` are where the lists live, `inspect <name>` reads one
  application, and `inspect` with nothing offers the list. `discover` is the
  name it used to have and still works, short forms and all.
- config show with nothing named is now the configuration entrascope is
  actually running with, as YAML, above the full paths it was read from and the
  directories it searched in order. Naming a file still prints that file, now
  with its path above it.
- Every menu comes back after the command it ran, rather than returning to the
  shell, and offers the way out rather than leaving it to be guessed at. A
  command that fails from a menu says so and the menu returns. A prompt for an
  argument takes a blank answer as going back. Escape goes back a level rather
  than ending the session.
- After reading an application the choice is a menu: back to the list, save it
  to a YAML file, or leave. It was a yes or no question, which could not offer
  the file.

### Fixed
- Investigation read the owners, federated credentials and role assignments of
  every object one call at a time, which on a tenant of several hundred was
  thousands of calls and minutes of waiting. Owners now come back with the
  page, expanded, and nothing else is read that no rule looks at. It also says
  what it is doing as it goes.
- The arrow keys did nothing while a search was being typed, so narrowing five
  hundred applications to two left no way to choose either. Movement now works
  the same whether or not a search is in progress.
- inspect read every object in the tenant in full before it could offer a list
  of names, which on a directory of several hundred meant over a thousand calls
  and minutes of silence that looked like a hang. The list is now names and
  identifiers only, two calls, and everything else is read for the one
  application chosen.
- Every query asks for the fields it projects rather than whole objects.
- A long read now says what it is doing while it does it.
- The chooser gave no sign that the search key had registered, so pressing it
  again was the natural response, and the second slash went into the term and
  made every match fail. The search is shown as it is typed, with a count of
  what matched, and a slash typed first is ignored.
- Identifiers line up in a column rather than starting wherever each name ends.
- Managed identities are kept out of the chooser. Azure creates one per
  resource and Defender one per subscription, so a tenant holds hundreds of
  them. What was hidden is counted and --all includes them.
- A lookup the identity is not allowed to make now names the grant that would
  have answered it, rather than only reporting the refusal.
- "Reading the applications in the tenant" is now "Reading applications".

### Added
- The chooser is coloured by meaning, for a dark terminal: an expired
  credential red, one expiring amber, an OAuth or OpenID Connect application
  orange, a SAML application violet, a managed identity in the quietest colour
  on the screen. The palette is configuration, under fields.display.chooser,
  and the chooser paints its own background so the colours are read against
  the one they were chosen for. A terminal with eight colours falls back to the
  nearest of them, and one with none falls back to bold, dim and reverse.
- The chooser sorts: s cycles between name, name reversed, newest and oldest.
  Page up and page down move a screen at a time.

### Added
- A refusal that names a Microsoft Graph permission now prints the exact
  command that grants it, with the identifier for that permission and the
  application entrascope authenticated as, followed by the consent that
  actually grants it.
- Authentication_MSGraphPermissionMissing is explained.

### Fixed
- A credential file that is present but unsafe now stops the command instead of
  being passed over. The contract has always said to refuse to run, and quietly
  authenticating some other way is not refusing: it leaves a secret readable by
  others while the tool carries on as though nothing were wrong. A file that is
  absent is still passed over, and naming a source with --auth still leaves the
  file alone.
- Any failure now says which identity answered and what was passed over to
  reach it. The reason a credential file was skipped used to be a log line
  nobody would see unless they happened to be reading at info level.

### Added
- A credential file can be named: --credentials takes a bare name, which is a
  file inside the credential directory, or a path. ENTRASCOPE_CREDENTIAL_FILE
  does the same for a shell. Naming one means the file source. One file per
  tenant is ordinary and there was no way to say so.
- When the expected credential file is absent, the ones that are present are
  listed, with the command to use one of them.
- The doctor says which credential file it looked at even when another source
  answered, and names every source it passed over and why. A source that was
  expected to answer and quietly did not was invisible.

### Changed
- Configuration of your own lives in ~/.config/entrascope, outside the package,
  so upgrading never touches it, and is layered over the shipped defaults.
  Copy only the files you want to change, with config export --only, and
  everything else comes from underneath. A release that adds a setting is
  picked up without anybody doing anything, and a file written two releases ago
  keeps working. A directory named with --config-dir is used as it stands.
- config path says what each directory is, whether it is the packaged copy that
  an upgrade replaces, and what the one in force is layered over.

### Fixed
- The version check cannot fail a command. Every step of it now sits behind one
  boundary rather than a list of the failures somebody thought of, and the
  caller has a second one, so no future change to the check can stop a command
  running. A cache holding valid JSON of the wrong shape, a timestamp that is
  not a number and a release tag in an unexpected shape are each ignored.
- A value typed at a prompt is a value. Without a separator, an error message
  beginning with a dash, or the word --help, was parsed as an option instead of
  answered.
- Whatever the installer prints during an upgrade goes through redaction, since
  an index URL can carry credentials and the installer echoes it.

### Changed
- The README is checked by the test suite. Every command inside a fenced block
  is resolved against the real command line with its real options, and the
  application types, output formats, authentication sources and top level
  commands are checked against the code that defines them.
- The README no longer tells somebody to pass --auth azure-cli for the quick
  route, which has not been needed since the Azure CLI session began resolving
  automatically, and it now documents the application types and the commands
  added since it was written.

### Added
- entrascope upgrade, which works out how this copy was installed and uses the
  right command through the running interpreter rather than whichever pip is on
  the path. On a Python that something else manages it refuses and shows the
  safe routes, with --break-system-packages there for somebody who decides
  otherwise. --check reports without changing anything.
- A version check against the published releases, at most once a day, cached,
  with a short timeout, skipped for machine readable output and when there is
  no terminal, and silent on any failure. ENTRASCOPE_NO_UPDATE_CHECK switches
  it off.
- A command group given no subcommand now offers its commands rather than only
  listing them, and asks for whatever the chosen one cannot do without. Piped
  or in a script it prints the help and exits exactly as before.
- inspect returns to the list after showing an application.

### Fixed
- inspect walked the whole directory twice, once to build the chooser and once
  to inspect what was chosen. It reads once now.
- The log said what it had discovered but never which application it was
  inspecting.

### Changed
- An application that exposes an API and registers no redirect URI is
  classified as api-or-resource rather than as a public client. It signs nobody
  in, and calling it a client sent the reader looking for a sign in that never
  happens.
- A web application holding no credential is classified as web-client rather
  than confidential-client. Confidential means it holds a secret.
- An enterprise application whose kind a service principal does not determine
  is classified as enterprise-application rather than confidential-client. The
  registration decides the client type and the service principal does not carry
  it.
- Discovery reports whether an application exposes an API.

### Fixed
- The fact that an application exposes an API was computed and then not carried
  into the projection, so it was reported as false on the very applications
  that were classified by it.
- AADSTS5002710 and AADSTS700024, the client assertion failures, and
  Microsoft.Online.Workflows.ValidationException are explained. All three were
  observed driving real flows against a tenant.

### Added
- entrascope config path, export and show. The configuration ships inside the
  installed package, where it is awkward to edit and is replaced on upgrade, so
  there is now a supported way to see which directory is in force and to take a
  copy. A test asserts the wheel still carries it.
- The configuration is readable as an MCP tool, so an assistant can learn the
  vocabulary. Exporting is deliberately not exposed, and the reason is recorded
  where the parity test can read it.

### Security
- Values that reach a query are escaped. A single quote in an application
  filter could end the literal and rewrite the filter, and a double quote in a
  Kusto parameter could rewrite the predicate, which matters more because Kusto
  expresses a great deal more than filtering. Escaping happens where each query
  is built rather than at the call sites, numbers are coerced, control
  characters are removed and lengths are bounded.
- Values that reach a terminal have their control characters removed. A display
  name in a directory is somebody else's input and a terminal obeys escape
  sequences. In the plain format newlines and tabs are replaced as well,
  because there a line is a record and a tab is a column.
- The remote server refuses to start unless its canonical URI is https, or a
  loopback address. It is published in the protected resource metadata and
  clients bind their tokens to it.

### Fixed
- A network failure reached the user as a stack trace from the transport. A
  refused connection, a name that does not resolve, a proxy that will not talk,
  a certificate that cannot be verified and a read that timed out are now the
  one structured error, each named separately because each needs a different
  remediation, and each with an entry in the error mapping.
- A success carrying something that is not JSON, which is what a captive portal
  answering in place of the service looks like, is reported as that rather than
  as a decoding error.
- A failure with no reply at all no longer claims the service returned status
  zero.
- Two workers missing the token cache at the same moment each asked the
  authority for a token nobody needed.
- Replacing the log handlers left their files open, leaking a descriptor on
  every reconfiguration. A file destination now gets a handler that owns its
  file, and a standard stream one that owns nothing, so closing does the right
  thing in both cases.
- The credential file mode is read from the open descriptor rather than from the
  path, so what was checked and what was read cannot be two different files.
- An investigation enumerated every application and service principal with no
  ceiling. There is now a configured limit and a truncated answer says so.
- A requests session was shared between tasks that could run at the same time.
  Dividing a list of sessions by the worker count hands the same one to items
  that run concurrently as soon as there are more items than workers. Each
  worker now has its own, from thread local storage.
- The correlation id and the context fields did not reach the worker threads,
  because a thread does not inherit context variables. The caller's context is
  now carried across, one copy per task.
- fastmcp is a dependency again. The servers are one of the three surfaces this
  tool exists to provide, and an install where one of them is missing is a
  broken promise. The clear message for a broken install stays.
- The package ships a py.typed marker, so anything importing it can use the
  type hints rather than treating every symbol as Any.

### Added
- entrascope inspect maps an application onto the provisioning vocabulary:
  the platforms in the words the provisioner uses, the exposed API, the on
  behalf of configuration, the claims, the tags and the service management
  reference, and an application type name with the evidence behind it. The
  vocabulary is configuration and is reported as provisional until an
  authoritative list replaces it.

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
