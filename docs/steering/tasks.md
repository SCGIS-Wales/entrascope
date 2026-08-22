# entrascope: phased build plan

Approved on 22 August 2026, revision 3. Answers to the open questions in
section 5, as given on approval: proceed with every default. Merge each green
pull request automatically, run the phases in sequence, keep the release jobs
gated by `ENABLE_RELEASE`, and leave branch protection alone until asked.

Derived from the steering document set. Written in the house style the steering
document mandates: Oxford English, no dash punctuation in prose, functional
Python only.

Changes in revision 3, at your request:
- A full GitHub Actions pipeline modelled on `/Users/ssddgreg/dcert`, landing in
  Phase 0 rather than Phase 9 so that every pull request has checks from the
  first one. See section 3.
- A branch, pull request, green checks, merge protocol applied to every phase.
  See section 0.10.

Changes in revision 2:
- HTTP client is `requests`, not `httpx`. See section 0.3. This makes the whole
  codebase synchronous, changes the mocking library, and changes the retry
  mechanism.
- A single common logger used by every module. See section 0.4.
- The same "one implementation, used everywhere" treatment applied to the four
  other cross cutting concerns that were about to be duplicated. See section
  0.5. Tell me if you meant something else by "etc" and I will fold it in.
- Authentication now includes an Azure CLI source. See section 1a.

---

## 0. Assumptions, decisions and deviations

These are the points where I depart from the steering document or where the
document is silent. Correct any of them on approval and I will fold the change
into Phase 0.

### 0.1 Naming

The steering document calls the project `entra-logscope` under
`github.com/dejangregor`. The actual repository is `entrascope` under
`github.com/SCGIS-Wales`, and the committed README already says entrascope.

Proposal: adopt entrascope throughout.

| Item | Value |
| --- | --- |
| Distribution name (PyPI) | `entrascope` |
| Import package | `entrascope` (src layout) |
| Console script | `entrascope` |
| Repository | `SCGIS-Wales/entrascope` |
| Credential path | unchanged: `~/.entra/provisioner-credentials.json` |

### 0.2 Dependency versions verified against PyPI today (22 August 2026)

I queried PyPI rather than trusting the pins in the steering document.

| Package | Steering pin | Latest on PyPI | Action |
| --- | --- | --- | --- |
| requests | not present | 2.34.2 | add, `>=2.32.0`, replaces httpx |
| responses | not present | 0.26.2 | add, `>=0.26.0`, replaces respx |
| httpx | >=0.28.1 | 0.28.1 | remove from our dependencies |
| respx | >=0.22.0 | 0.23.1 | remove from our dependencies |
| fastmcp | >=3.4.7 | 3.4.7 | keep |
| mcp | >=1.9.0 | 2.0.0 | drop the direct pin, let fastmcp own the resolution |
| azure-monitor-query | >=1.4.0 | 2.0.0 | move to >=2.0.0, see note below |
| azure-identity | >=1.25.3 | 1.25.3 | keep |
| pyjwt[crypto] | >=2.13.0 | 2.13.0 | keep |
| pydantic | >=2.13.0 | 2.13.4 | keep |
| click | >=8.3.0 | 8.4.2 | raise to >=8.4.0 |

Note on azure-monitor-query 2.0.0: the 2.x release removed `MetricsClient` and
`MetricsQueryClient`. `LogsQueryClient` remains, and logs are all entrascope
needs, so 2.x is safe and is the right floor.

Note on `mcp`: pinning both `fastmcp` and `mcp` invites a resolution conflict
now that mcp has gone to 2.0.0. fastmcp declares the constraint it needs.

Note on httpx: it will still be present in the resolved environment because
fastmcp and mcp depend on it. It will not be imported anywhere in `src/`, and a
guard test enforces that.

Local Python is 3.14.7 at /opt/homebrew/bin/python3.14, standard GIL build,
which matches the steering requirement.

### 0.3 HTTP stack: requests, and what follows from it

Adopting `requests` is the better choice here and it turns out to be more than
a swap. azure-core, which azure-identity and azure-monitor-query both sit on,
declares `requests>=2.21.0` as a hard dependency and uses it as its default
synchronous transport. So requests is already in the tree whatever we do.
Choosing it for the Graph calls too gives one HTTP stack, one connection pool
configuration, one proxy and TLS story, one set of environment variables, and
one mocking library across every outbound call the tool makes. With httpx we
would have carried two.

Four consequences, all of which I have built into the plan:

1. **The codebase becomes synchronous.** requests has no async interface. Every
   Graph and Monitor function is a plain `def`. This is the simpler shape for a
   CLI and it removes `asyncio` from the CLI, doctor and discovery paths
   entirely. FastMCP tool functions may be synchronous, so the MCP surface is
   unaffected.
2. **Where concurrency is genuinely needed**, and it is needed, because
   discovery over a large tenant is hundreds of Graph calls, use
   `concurrent.futures.ThreadPoolExecutor` with `max_workers` read from
   `config/retry.yaml`. requests is thread safe when each thread holds its own
   session, so the session factory is per worker. Threads suit this workload
   because it is entirely IO bound.
3. **Retry and backoff move into the transport.** `urllib3.util.Retry` mounted
   on an `HTTPAdapter` handles the 429 and 5xx classes, honours `Retry-After`,
   and applies exponential backoff, all configured declaratively from
   `config/retry.yaml`. This is less code than a hand rolled retry loop around
   httpx and it is better tested. Graph specific throttling behaviour that
   urllib3 cannot express, such as the `@odata.nextLink` interaction, stays in
   our paging function.
4. **Mocking changes from respx to responses.** Same fixture style, same
   assertions on request bodies and headers, and it also intercepts the calls
   azure-core makes, which respx could not.

`requests.Session` is a class and `HTTPAdapter` is a class. Both are third
party framework objects, instantiated inside a factory function marked with the
`# framework contract:` comment the steering document prescribes. No business
logic goes near them.

One module, `src/entrascope/http.py`, owns the session factory and the single
`request` wrapper that every outbound call goes through. A guard test asserts
that `requests` is imported nowhere else in `src/`, and that `httpx` is
imported nowhere at all.

### 0.4 The common logger

One module, `src/entrascope/logger.py`, exposes `get_logger(name)` and nothing
else that other modules need. Every module in `src/` obtains its logger through
it. Nothing calls `logging.getLogger` directly and nothing calls `print` except
the CLI rendering layer.

What the common logger provides:

- Configuration read from `config/logging.yaml`: level, format, destination,
  and whether to emit JSON lines or human readable text. Human readable is the
  CLI default; JSON lines is the default for both MCP servers.
- **Redaction as a logging filter**, so redaction is structural rather than
  something each call site has to remember. The secret, bearer tokens, client
  assertions and any value matching the configured secret patterns are replaced
  before a record reaches a handler. This is the mechanism behind the sentinel
  guard in section 1.
- **A correlation id** held in a `contextvars.ContextVar`, generated per CLI
  invocation, per MCP tool call and per HTTP request served by the remote
  server, and attached to every record automatically. This is what makes a
  single failing tool call traceable through the Graph calls it caused.
- **Standard context fields** on every record: the authentication source in
  use, the tenant id, the Graph endpoint being called and the elapsed
  milliseconds. On the remote server, additionally the token `azp` and `sub`,
  and never the token itself.
- A `logging.Formatter` subclass for the JSON line format, which is a framework
  contract exception and is marked as one. All formatting decisions live in
  free functions the subclass calls.

Because `logger.py` and `redaction.py` underpin everything else, they land in
Phase 1 and every later phase depends on them.

### 0.5 The other cross cutting concerns

The same treatment, one implementation used everywhere, applied to four things
that would otherwise be reimplemented in the CLI, the stdio server and the HTTP
server independently:

| Concern | Module | Rule |
| --- | --- | --- |
| HTTP transport | `http.py` | every outbound call, one session factory, one retry policy |
| Logging | `logger.py` | `get_logger` only, no direct `logging.getLogger`, no `print` outside rendering |
| Configuration access | `config.py` | one loader, one cached accessor, no module reads YAML itself |
| Error taxonomy | `errors.py` | one error DTO, one mapping function, one place AADSTS codes are interpreted |
| Rendering and exit codes | `render.py` | one table, json and yaml renderer, one exit code map, shared by CLI and MCP |

`render.py` is an addition to the steering document's tree. Without it the MCP
tool results and the CLI `--output json` payloads drift apart, and they must not,
because they are the same data.

### 0.6 MCP protocol revision

The steering document sets the build target to revision 2025-11-25 and notes
that 2026-07-28 was scheduled to publish on 28 July 2026, which is now four
weeks past. I will not assert which revision is live. Phase 8 opens with a
verification task: read the protocol version fastmcp 3.4.7 actually negotiates
from the installed source, record it in `docs/steering/mcp-server.md`, and
assert it in a test so a dependency bump that changes it fails CI.

### 0.7 The FastMCP audience override

The steering document sets `verifier._audience`, a private attribute, citing
two upstream issues. Phase 8 will read the installed fastmcp 3.4.7 source first
and prefer a public parameter if one exists. If no public route exists I will
use the private attribute, isolate it in a single function, mark it with the
framework contract comment, and cover it with a test that fails loudly if the
attribute disappears on upgrade.

### 0.8 Scope boundaries

Out of scope unless you say otherwise: Dynamic Client Registration, Client ID
Metadata Documents, an OAuth Proxy for arbitrary clients, On Behalf Of token
exchange, and `AppRoleAssignment.ReadWrite.All`. The remote server uses the
separate service identity pattern with application permissions, which the
steering document names as the default.

Also out of scope: any write operation against the directory. entrascope reads.

### 0.9 What I cannot do for you

Console or tenant operations that need your credentials and consent. Each is
listed again against the phase it blocks.

1. Either run `az login` and use the Azure CLI credential source (section 1a),
   or create or nominate the Entra app registration and client secret and place
   the credential file at `~/.entra/provisioner-credentials.json` with mode 0600
   in a directory with mode 0700.
2. For the application credential sources, add the four Graph application
   permissions and grant admin consent. Not needed for the Azure CLI source,
   where your own directory roles apply instead.
3. Assign Log Analytics Reader on the workspace.
4. Register the PyPI and TestPyPI pending publishers and create the GitHub
   environments named `pypi` and `testpypi` with protection rules.
5. Decide whether to enable branch protection on `main` requiring the checks in
   section 3. I have admin on the repository so I can apply it with `gh api`,
   but it changes how the repository behaves for everyone, so I will not touch
   it without your say so.
6. For the remote server: expose an API on the app registration, set the
   Application ID URI, define the scope, and set `requestedAccessTokenVersion`
   to 2.

I will supply the exact commands and, where a portal step is unavoidable, the
exact navigation and the Microsoft Learn URL.

### 0.9a Forward proxies and certificate trust

Added during phase 5, at Dejan's request, and implemented there rather than
reopening phase 2.

EARS: WHEN a forward web proxy is named in the environment, the system SHALL
route every outbound call through it. WHEN a certificate authority bundle or
directory is named in the environment, the system SHALL verify TLS against it,
and SHALL NOT disable verification because a named path does not exist.

The variable names are configuration in the `network` section of
`config/retry.yaml`. The resolved setting reaches azure-identity and
azure-monitor-query as well, and `doctor` reports what is in force. Detail in
`docs/steering/credentials-and-security.md`.

### 0.10 Branch, pull request and merge protocol

One phase is one pull request. Ten phases, ten pull requests, each one green
before it merges. Nothing is committed directly to `main`.

For each phase:

1. Branch from an up to date `main` as `phase/NN-slug`, for example
   `phase/00-scaffold`, `phase/02-transport-graph-monitor`.
2. Commit in conventional commit form, matching the prefixes dcert already
   uses: `feat:`, `fix:`, `chore:`, `ci:`, `docs:`, `test:`, `deps:`.
3. Run the full local gate before pushing. A red local gate never becomes a
   pull request.
4. Push the branch and open the pull request with `gh pr create`. The body
   carries the phase acceptance criteria as a checklist, the local gate output,
   and the list of tests added.
5. Wait on the checks with `gh pr checks --watch`. Every required check must be
   green. If one fails I fix it on the branch and push again. I do not merge on
   red, I do not rerun a check hoping for a different answer, and I do not use
   `[skip ci]`.
6. Merge with `gh pr merge --squash --delete-branch` once every check is green.
7. Report the pull request URL, the check results and the merge commit before
   moving to the next phase.

I have confirmed the mechanics are available: `gh` is authenticated as `api-py`
with admin on `SCGIS-Wales/entrascope` and holds the `workflow` scope, so it can
push workflow files. Squash merging is enabled. `main` currently has no branch
protection, and `delete_branch_on_merge` is off, which is why the merge command
passes `--delete-branch` explicitly.

Two notes worth your attention. First, the repository is public, so every
fixture, KQL template and error mapping is world readable. Fixtures will carry
no real tenant identifiers, object ids or user principal names, and a test
asserts the fixture directory contains no GUID matching your tenant. Second,
because you asked for the checks to be green and then the pull request merged,
my default is to merge automatically on green and report afterwards. Say the
word and I will instead stop at each green pull request and wait for your
review before merging.

---

## 1. Standing gates

Every phase ends green or it does not end. The gate for all phases from Phase 0
onward is:

```bash
ruff check . && ruff format --check . && mypy --strict src && pytest
```

Plus five project specific guards, added in Phase 0 and enforced from then on:

1. **No hardcoded endpoints.** A test greps `src/` for `https://`, `api://` and
   the known table names and fails on any hit outside the config loader.
2. **No classes.** A test parses the AST of every module and fails on any class
   definition not carrying a `# framework contract:` comment.
3. **No secret in output.** A test drives every command and every MCP tool with
   a sentinel secret and asserts the sentinel never appears in stdout, stderr
   or any log record.
4. **One HTTP stack.** A test asserts `requests` is imported only in `http.py`
   and `httpx` is imported nowhere in `src/`.
5. **One logger.** A test asserts no module calls `logging.getLogger` directly
   and no module outside `render.py` calls `print`.

Coverage floor: 90 percent on `src/`, made a hard failure in Phase 2 once there
is real code to cover.

---

## 2. Phases

### Phase 0. Scaffold, steering documents and guards

Deliverables:
- Repository tree per the steering document, renamed to `entrascope`, plus the
  two added modules `http.py`, `logger.py` and `render.py`.
- `CLAUDE.md` at the root, from the steering document with the naming
  corrections and the requests decision recorded.
- All eleven documents under `docs/steering/`, including this plan promoted to
  `docs/steering/tasks.md`. `tech-stack.md` carries the requests justification
  from section 0.3 in place of the httpx justification.
- `pyproject.toml` with the corrected pins from section 0.2, hatchling backend,
  src layout, ruff and mypy strict configuration, pytest configuration.
  `asyncio_mode = "auto"` is retained solely for the FastMCP client tests.
- Config files with schemas and full content where the steering document
  supplies it: `endpoints.yaml`, `tables.yaml`, `error-codes.yaml`,
  `capabilities.yaml`, `retry.yaml` (now also carrying the urllib3 Retry
  parameters and `max_workers`), `fields.yaml`, `logging.yaml`, and the three
  KQL templates under `config/kql/`.
- `.pre-commit-config.yaml`, `LICENCE` (MIT), `CHANGELOG.md`.
- The GitHub Actions pipeline in section 3, in its Phase 0 form: `ci.yml` with
  the lint, typecheck, guards, test, security and build jobs, plus `codeql.yml`
  and `dependabot.yml`. The later jobs are added by the phase that makes them
  meaningful, so that no job is ever present and skipped.
- Typed stubs for every module in `src/entrascope/`.

Acceptance:
- `uv pip install -e ".[dev]"` succeeds on Python 3.14.7.
- `entrascope --help` prints the command group.
- All five guards pass against the stubs.
- The pull request for this phase is green on every check and merges. This is
  the first proof that the pipeline itself works.

Tests: `test_cli_help`, `test_config_loads`, `test_guard_no_hardcoded_endpoints`,
`test_guard_no_classes`, `test_guard_no_secrets`, `test_guard_one_http_stack`,
`test_guard_one_logger`.

Blocked by you: nothing. This phase runs entirely offline.

### Phase 1. Configuration, logging and credentials

The foundation every later phase imports.

Deliverables: `config.py`, `logger.py`, `redaction.py`, `credentials.py`,
`models.py` (the first DTOs as frozen NamedTuples).

Behaviour:
- Pure functions to load, merge and validate every YAML file, with a pydantic
  schema per file used for validation only, and one cached accessor.
- The common logger as specified in section 0.4: `get_logger`, the redaction
  filter, the correlation id context variable, the standard context fields, the
  JSON and human formatters.
- Credential loading from `~/.entra/provisioner-credentials.json` with keys
  exactly `ClientID`, `Secret`, `TenantID`, and an alternative filename inside
  `~/.entra` taken from configuration.
- Permission enforcement: `stat` the file and directory, mask `st_mode` with
  `0o777`, require `0o600` and `0o700`, refuse to run otherwise.
- The authentication source chain in section 1a.

EARS: WHEN the credential file mode is not 0600, the system SHALL refuse to run
and SHALL print remediation without revealing the secret.

Acceptance: refuses on a 0644 file or a 0755 directory with a remediation
message naming the exact chmod; the secret never reaches a handler even when a
module logs the whole credential structure at debug level; the correlation id
is present on every record.

Tests: `test_perms_reject`, `test_perms_accept`, `test_redaction`,
`test_logger_redacts_secret_in_structure`, `test_logger_correlation_id`,
`test_logger_json_format`, `test_auth_source_file`, `test_auth_source_env`,
`test_auth_source_azure_cli`, `test_auth_source_default_credential`,
`test_auth_source_precedence`, `test_auth_source_azure_cli_absent`,
`test_config_schema_rejects_bad_yaml`.

Blocked by you: nothing for the tests, which use temporary files and a stubbed
`az`. For a live run, either item 1 in section 0.9, or simply `az login`.

#### Phase 1a. Authentication sources

Four sources, resolved in this order unless `--auth` names one explicitly. The
active source is reported by name in `doctor` output and attached to every log
record, so it is always obvious which identity a result came from.

| Order | `--auth` value | Mechanism | Identity kind |
| --- | --- | --- | --- |
| 1 | `file` | `~/.entra/provisioner-credentials.json` client credentials | application |
| 2 | `env` | `ARM_CLIENT_ID`, `ARM_CLIENT_SECRET`, `ARM_TENANT_ID` | application |
| 3 | `azure-cli` | `AzureCliCredential`, the session from `az login` | delegated user |
| 4 | `default` | `DefaultAzureCredential`, the full azure-identity chain | varies |

What the Azure CLI source changes:

- It needs no credential file, no client secret and no app registration. If you
  have run `az login` you can run entrascope immediately.
- The token is delegated, carrying your own user identity, so authorisation
  comes from your directory roles rather than from Graph application
  permissions. Global Reader, Security Reader or Reports Reader will cover the
  read surface entrascope needs.
- `doctor` check 3 therefore changes shape under this source. It inspects the
  `scp` claim and your directory role assignments instead of the `roles` claim,
  and its remediation names the directory role to request rather than the
  `az ad app permission add` command.
- Not every scope is guaranteed. Some Graph scopes are not pre authorised for
  the Azure CLI client in every tenant, and where a scope is refused entrascope
  reports the missing scope and names the fallback rather than failing
  opaquely.
- It suits interactive diagnosis. Unattended and remote MCP operation stay on
  the application credential sources, because a delegated CLI session is not
  present in a container.

Implementation is `AzureCliCredential` from azure-identity, not shelling out to
`az account get-access-token`, so token caching and refresh are the library's
problem. If the Azure CLI is absent or no session exists, the source is skipped
during chain resolution and, when selected explicitly, produces a clear
remediation naming `az login`.

### Phase 2. HTTP transport, Graph and Monitor clients

Deliverables: `http.py`, `graph.py`, `monitor.py`.

Behaviour:
- `http.py`: the session factory, `HTTPAdapter` with `urllib3.util.Retry`
  configured from `config/retry.yaml`, default timeouts, the user agent string,
  and one `request` function through which every outbound call passes, logging
  method, host, status and elapsed milliseconds through the common logger.
- `graph.py`: synchronous functions against Graph endpoints read from
  `config/endpoints.yaml`. No SDK, no fluent API, no endpoint literals. Token
  acquisition for the active authentication source, cached in a closure and
  refreshed on expiry. `@odata.nextLink` paging. Optional threaded fan out for
  the per object calls discovery needs, with `max_workers` from configuration
  and one session per worker.
- `monitor.py`: a functional wrapper over `LogsQueryClient` taking a KQL
  template name plus parameters and returning rows as DTOs.
- Every Graph and token error surfaced as the single error DTO from section
  0.5, carrying the AADSTS or Graph code, ready for Phase 4 mapping.

Acceptance: `responses` mocked calls return typed DTOs; retry, backoff and
`Retry-After` handling are observable in tests; a threaded fan out over fifty
mocked objects completes and preserves ordering; the endpoint and HTTP stack
guards still pass; the coverage floor becomes a hard failure.

Tests: `test_session_factory_retry_config`, `test_request_logs_context`,
`test_graph_list_apps`, `test_graph_paging`, `test_graph_throttle_retry_after`,
`test_graph_fanout_threaded`, `test_token_acquisition`,
`test_token_cache_refresh`, `test_logs_query`, `test_error_dto_from_aadsts`.

Blocked by you: nothing. Everything is mocked.

### Phase 3. Discovery

Deliverables: `discovery.py`, expanded `models.py`.

Behaviour: enumerate `applications` and `servicePrincipals` and project, for
each, sign in audience, redirect URIs, delegated `oauth2PermissionScopes` and
application app roles both requested and granted, owners, `passwordCredentials`
and `keyCredentials` with `endDateTime` expiry, `federatedIdentityCredentials`,
SAML configuration (`identifierUris`, `replyUrls`, claims mapping policy,
signing certificate expiry) and `appRoleAssignmentRequired`.

Classification must cover confidential clients, public clients, native and
mobile and desktop, single page applications, SAML gallery and non gallery
enterprise applications, managed identities, and workload identity federation
applications.

Acceptance: fixture payloads for each application type produce the correct DTO
and classification; credentials inside a configurable expiry window are
flagged, and already expired credentials are flagged distinctly.

Tests: `test_discovery_types` (one case per application type),
`test_credential_expiry`, `test_saml_projection`,
`test_federated_identity_projection`, `test_assignment_required`.

Blocked by you: nothing. Fixtures are synthetic and scrubbed of tenant
identifiers.

### Phase 4. Log interrogation and error mapping

Deliverables: `logs.py`, `errors.py`.

Behaviour: query `directoryAudits` filtered to category `ApplicationManagement`,
interactive and non interactive user sign ins, service principal and managed
identity sign ins, `MicrosoftGraphActivityLogs` and provisioning logs, by both
routes, the Graph reporting APIs and Log Analytics KQL. Map AADSTS and Graph
error codes to meaning, likely cause, remediation and Learn URL from
`config/error-codes.yaml`, including the `Application.ReadWrite.OwnedBy` versus
`Application.ReadWrite.All` distinction, the "Users can register applications"
tenant setting, restricted management administrative units and missing admin
consent.

The module states plainly, in code comments and in CLI help, that Entra
directory operations do not appear in the Azure subscription Activity Log.

Acceptance: every code in the configuration file maps to its configured text
and URL; unknown codes return a safe default naming the code and linking to the
Microsoft reference page; both query routes return the same DTO shape.

Tests: `test_error_mapping`, `test_error_mapping_unknown_code`,
`test_signin_query_graph`, `test_signin_query_kql`,
`test_audit_applicationmanagement`, `test_graph_activity_query`,
`test_docs_urls_wellformed`.

Blocked by you: nothing for tests. A live run needs items 1, 2 and 3 in section
0.9, or `az login`.

### Phase 5. CLI foundation, rendering and doctor

Pulled ahead of the rest of the CLI, per recommendation 2 of the steering
document, because doctor is the fastest route to telling you why an app
registration operation failed.

Deliverables: `render.py`, `cli.py` (group, global options including `--auth`
and `--output`, correlation id setup, logger wiring), `capabilities.py`,
`doctor.py`.

Doctor checks:
1. Credential file present, directory 0700, file 0600, or the active source
   reported as one that needs no file.
2. Token acquisition against the configured authority.
3. Authorisation, read from the live token rather than trusted from a table.
   Under an application source, each required Graph permission must appear in
   the `roles` claim, and a failure prints the exact `az ad app permission add`
   and `admin-consent` commands with the app role GUIDs from configuration and
   the Learn URL. Under the Azure CLI source, the `scp` claim and the signed in
   user's directory roles are checked instead, and a failure names the
   directory role to request. The active source heads the report.
4. Licence tier from `subscribedSkus`, mapped to available capabilities,
   reported as observed rather than asserted as entitlement.
5. Each diagnostic setting category enabled and routed: `AuditLogs`,
   `SignInLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`,
   `ManagedIdentitySignInLogs`, `ProvisioningLogs`,
   `MicrosoftGraphActivityLogs`. Each miss prints what is missing, how to
   enable it, the required licence tier, the Security Administrator role
   requirement and the Learn URL.

Acceptance: pass and fail rows render; `--output yaml` emits the machine
readable capability report; a Free tier tenant produces reduced capability rows
rather than errors; the exit code is non zero when any check fails and comes
from the shared exit code map.

Tests: `test_doctor_pass`, `test_doctor_missing_diagnostics`,
`test_doctor_missing_permission`, `test_doctor_free_tier`,
`test_doctor_yaml_output`, `test_doctor_exit_code`,
`test_doctor_reports_auth_source`, `test_doctor_azure_cli_delegated_checks`,
`test_render_parity_table_json_yaml`.

Blocked by you: for the first live run, either `az login` alone, or items 1, 2
and 3 in section 0.9. The tests are fully mocked, so the phase completes
without either.

### Phase 6. Remaining CLI surface

Deliverables: the command groups `discover apps`, `discover sps`, `logs audit`,
`logs signins`, `logs graph-activity`, `errors explain <code>`, each rendering
through `render.py` and honouring `--output json` and `--output yaml`.

Acceptance: every command runs against mocks and prints a table; the secret
sentinel never appears; `--help` on every command is Oxford English and free of
dash punctuation, checked by a test.

Tests: `test_cli_discover`, `test_cli_logs`, `test_cli_errors`,
`test_cli_output_formats`, `test_help_text_style`.

### Phase 7. Local stdio MCP server

Deliverables: `mcp_tools.py` (the shared tool surface), `mcp_stdio.py`.

Behaviour: expose the Phase 3 to 5 functions as MCP tools over stdio with no
OAuth, credentials from any source in section 1a, including the Azure CLI
session, which is the convenient choice for a locally launched server. Tool
functions are synchronous, which FastMCP supports. Every tool returns
structured content built by `render.py`, so an MCP result and a CLI
`--output json` payload are the same bytes. Logging switches to JSON lines with
a correlation id per tool call. Input validation on every tool.

Acceptance: the FastMCP in memory client lists the tools and calls discovery,
logs, errors and doctor tools, receiving structured content matching the
declared schema.

Tests: `test_mcp_tool_list`, `test_mcp_discover_tool`, `test_mcp_logs_tool`,
`test_mcp_doctor_tool`, `test_mcp_tool_input_validation`,
`test_mcp_no_secret_in_results`, `test_mcp_result_matches_cli_json`.

### Phase 8. Remote HTTP MCP server with Entra authorisation

Opens with the two verification tasks in sections 0.6 and 0.7.

Deliverables: `mcp_http.py`, Streamable HTTP transport only, plus the container.

Behaviour:
- `AzureJWTVerifier` inside `RemoteAuthProvider`, pure resource server, no
  proxy.
- Protected resource metadata at `/.well-known/oauth-protected-resource` per
  RFC 9728, listing the Entra v2.0 issuer and the supported scopes.
- 401 with a `WWW-Authenticate` header whose `resource_metadata` parameter
  points at that document, on missing or invalid tokens.
- Validation of `iss`, `aud`, `exp`, `nbf`, `azp` and `scp` or `roles`, with
  `aud` compared against the configured Application ID URI.
- The caller token is never forwarded to Graph. Graph calls use the server's own
  client credentials through the same `http.py` session factory.
- `/healthz`, CORS restricted to configured origins, rate limiting from
  configuration, and the common logger in JSON mode carrying the correlation
  id, the token `azp` and `sub`, and never the token itself.
- Multi stage Dockerfile on `python:3.14-slim`, non root user, read only
  filesystem where possible, bound to 0.0.0.0 behind a TLS terminating proxy.

EARS: WHEN a request presents no bearer token, the server SHALL respond 401
with a `WWW-Authenticate` header pointing to the protected resource metadata.
WHEN a token's `aud` does not equal the configured Application ID URI, the
server SHALL reject it.

Acceptance: locally minted RS256 tokens throughout. Correct audience, issuer and
scope is accepted. Wrong audience, wrong issuer, expired and missing scope are
each rejected with the correct status. A transport level assertion proves no
request to the Graph host ever carries the caller's token.

Tests: `test_http_401_no_token`, `test_http_wrong_audience`,
`test_http_wrong_issuer`, `test_http_expired_token`, `test_http_missing_scope`,
`test_http_valid_token`, `test_no_token_passthrough`,
`test_protected_resource_metadata`, `test_www_authenticate_header`,
`test_healthz`, `test_protocol_version_pinned`.

Blocked by you: item 5 in section 0.9 before any live client can connect. The
whole phase, including tests, completes without it because tokens are minted
locally.

### Phase 9. Release, publishing and documentation

Deliverables: the release half of the pipeline in section 3, that is the
`auto-tag`, `publish-testpypi` and `publish-pypi` jobs enabled for the first
time; README covering installation, the credential contract, the four
authentication sources, the three surfaces, a worked doctor example and a
permissions table; `SECURITY.md`; CHANGELOG promoted to `0.1.0`.

Acceptance: the pull request is green; on merge, `auto-tag` produces `v0.1.0`,
`publish-testpypi` succeeds, and `publish-pypi` succeeds after environment
approval, with PEP 740 attestations attached.

Blocked by you: item 4 in section 0.9, before the first tag.

---

## 3. The GitHub Actions pipeline

Modelled on `/Users/ssddgreg/dcert/.github/workflows/ci.yml`, keeping its
conventions so the two repositories feel the same: one `ci.yml` named
CI/CD Pipeline carrying both continuous integration and release, a separate
weekly `codeql.yml`, a grouped `dependabot.yml`, read only permissions at the
top level with write granted per job, actions pinned to their major tag, and
Trusted Publishing with no tokens anywhere.

Three things from dcert are worth copying deliberately rather than by habit:

- **The auto-tag job.** On a push to `main` it reads the latest `v*` tag,
  computes the next patch version, rewrites the version in `pyproject.toml` and
  `src/entrascope/__init__.py`, commits with `[skip ci]`, tags and pushes, and
  exports the version as a job output so the publish jobs in the same run use
  it. No second workflow run triggered by the tag push.
- **The publish retry.** dcert publishes in up to three attempts with 30 and 60
  second backoff, `skip-existing: true` on every attempt, the first two
  `continue-on-error` and the third not, because the Sigstore Rekor
  transparency log intermittently returns 5xx while generating attestations.
  That is a real failure mode and the mitigation is worth having from day one.
- **The install test.** dcert builds the wheel and then installs it into a clean
  environment and runs the console scripts, which catches packaging errors that
  an editable install never sees.

### 3.1 ci.yml jobs

| Job | Runs on | Purpose | Arrives in |
| --- | --- | --- | --- |
| `lint` | pull request and main | `ruff check` and `ruff format --check` | Phase 0 |
| `typecheck` | pull request and main | `mypy --strict src` | Phase 0 |
| `guards` | pull request and main | the five structural guards from section 1, as their own check so a breach is named on the pull request rather than buried in the test run | Phase 0 |
| `test` | pull request and main | `pytest` on a 3.14 matrix with `--cov=entrascope --cov-fail-under=90 --timeout=120` and an XML coverage report artifact | Phase 0 |
| `security` | pull request and main | `pip-audit` against the resolved dependency set, and a CycloneDX SBOM uploaded as an artifact, the Python counterpart of dcert's `cargo audit`, `cargo deny` and `cargo cyclonedx` job | Phase 0 |
| `build` | pull request and main | `python -m build` then `twine check dist/*`, dist uploaded as an artifact | Phase 0 |
| `install-test` | pull request and main | install the built wheel into a clean virtual environment and run `entrascope --help` and `entrascope doctor --help` | Phase 5 |
| `mcp-smoke` | pull request and main | start the stdio server and list the tools through the FastMCP client, dcert's integration test in spirit | Phase 7 |
| `docker` | main only | buildx, `docker/metadata-action`, push to `ghcr.io/scgis-wales/entrascope` | Phase 8 |
| `auto-tag` | main only, needs the checks above | semver patch bump, commit, tag, push, version exported as an output | Phase 9 |
| `publish-testpypi` | main only, needs `auto-tag` | Trusted Publishing dry run, environment `testpypi` | Phase 9 |
| `publish-pypi` | main only, needs `publish-testpypi` | Trusted Publishing with the three attempt retry, environment `pypi` | Phase 9 |

Everything up to and including `build` is a required check on a pull request.
Those are the health checks that must be green before I merge.

### 3.2 A gate on the release jobs

dcert tags a new patch version on every merge to `main`. Ten phase merges would
therefore produce ten releases of a package that is not finished. So `auto-tag`
and both publish jobs carry an additional condition on a repository variable,
`ENABLE_RELEASE`, which stays unset until Phase 9. The jobs are written and
reviewed early, and they simply do not fire until you set the variable. Say if
you would rather they were absent until Phase 9 instead.

### 3.3 codeql.yml and dependabot.yml

`codeql.yml` follows dcert exactly, weekly on Monday at 08:00 UTC plus
`workflow_dispatch`, with `languages: actions, python` rather than dcert's
`actions` alone, since we have Python to analyse.

`dependabot.yml` follows dcert's shape with three ecosystems, `pip`,
`github-actions` and `docker`, weekly on Monday, `api-py` as reviewer,
dcert's commit message prefixes, and groups for the families that move
together: `azure-*`, `pytest-*`, and `fastmcp` with `mcp`.

---

## 4. Sequencing summary

```
Phase 0  scaffold, steering docs, five guards      offline
Phase 1  config, common logger, credentials, auth  offline
Phase 2  requests transport, Graph, Monitor        offline, mocked
Phase 3  discovery                                 offline, mocked
Phase 4  logs and error mapping                    offline, mocked
Phase 5  render, CLI foundation, doctor            first live value
Phase 6  remaining CLI commands
Phase 7  stdio MCP server
Phase 8  HTTP MCP server and container
Phase 9  CI, PyPI, documentation
```

Each row is one branch, one pull request, one set of green checks and one
squash merge, per section 0.10.

Phases 0 to 4 need nothing from your tenant. The first point where your input
changes the outcome is the live run at the end of Phase 5, and `az login` is
enough for that.

## 5. Open questions

1. Confirm the name entrascope, per section 0.1.
2. Confirm the dependency corrections, per section 0.2, and the requests
   consequences in section 0.3, in particular that a synchronous codebase with
   threaded fan out is what you want.
3. Confirm what "etc" covered. Section 0.5 is my reading of it. If you meant
   something more specific, say so and I will revise before starting.
4. Confirm the authentication source order in section 1a, and whether the Azure
   CLI source should be tried before or after the environment variables.
5. Merge each green pull request automatically, which is how I have read your
   instruction, or stop at each green pull request and wait for your review?
6. Enable branch protection on `main` requiring the checks in section 3.1? I
   can apply it, but not without you asking.
7. Keep the release jobs present but gated by `ENABLE_RELEASE` from Phase 0, or
   leave them out of the pipeline until Phase 9? See section 3.2.
8. Run all ten phases in sequence, stopping only on a failed gate or a red pull
   request, or pause for your review at each phase boundary?
