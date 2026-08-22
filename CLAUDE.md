# CLAUDE.md — entrascope

You are building entrascope, a production ready tool that gives observability
over Microsoft Entra ID and Azure Monitor logs so an engineer can diagnose
authentication and authorisation failures across application registrations and
enterprise applications. Obey these hard rules at all times.

## Hard rules
1. Python 3.14 only. Use modern typing (PEP 585 built in generics, PEP 604
   X | Y unions, PEP 484 hints everywhere). Package with PEP 621 pyproject.toml.
2. Functional programming only. No classes for application logic. Use pure
   functions and function composition. Use typing.NamedTuple or frozen
   dataclasses for immutable data transfer objects only. Do NOT create object
   oriented service classes.
   Framework contract exception: where a third party framework requires a class
   (a logging.Formatter subclass, a Pydantic schema model, a requests.Session
   or HTTPAdapter, or a FastMCP provider such as AzureJWTVerifier or
   RemoteAuthProvider), you MAY subclass or instantiate it, but you MUST keep
   all business logic in free functions and document the exception with a
   comment beginning "# framework contract:".
3. Externalise ALL configuration into YAML files under config/. Nothing
   hardcoded: no endpoints, tenant ids, table names, KQL templates, retry
   values, field mappings, error code mappings or documentation URLs.
4. CLI uses click with command groups, subcommands and a console entry point.
5. British Oxford English spelling in all documentation, docstrings, help text
   and comments (organise, authorise, licence as noun, colour).
6. Avoid dash and hyphen punctuation in prose, help text sentences and docs.
   Hyphens in CLI flags, identifiers, package names and URLs are syntax and are
   fine.
7. Security: never log or print secrets. Redact everywhere. Validate credential
   file permissions at startup and refuse to run if unsafe.
8. Tests: pytest with fixtures, mocked HTTP via responses, and tests covering
   the MCP tool surface. Keep coverage high.

## One implementation, used everywhere
- HTTP transport lives in `http.py`. `requests` is imported nowhere else in
  `src/`, and `httpx` is imported nowhere at all.
- Logging goes through `logger.get_logger`. Nothing calls `logging.getLogger`
  directly, and nothing calls `print` outside `render.py`.
- Configuration is read by `config.py` alone. No module opens a YAML file.
- Error interpretation lives in `errors.py`. One error DTO, one mapping.
- Rendering and exit codes live in `render.py`, shared by the CLI and the MCP
  tool surface, so an MCP result and a CLI `--output json` payload are the same
  bytes.

## Credential contract (reuse exactly, do not change)
- Credentials live at ~/.entra/provisioner-credentials.json
- JSON keys are exactly ClientID, Secret, TenantID
- File mode MUST be 0600; directory ~/.entra MUST be 0700. Validate at startup
  and refuse to run if group or world readable.
- Allow an alternative filename inside ~/.entra via configuration.
- Authentication sources, in resolution order: the credential file, the ARM_*
  environment variables, the Azure CLI session, then DefaultAzureCredential.
  Each is selectable explicitly with --auth.
- The secret must never be logged or printed.

## Build order (phases)
CLI first, then stdio MCP server, then HTTP MCP server with Entra OAuth. Do not
start a phase until the previous phase tests pass. See docs/steering/tasks.md.

## Branch and merge protocol
One phase is one pull request. Branch as `phase/NN-slug`, run the full local
gate before pushing, open the pull request, wait for every check to pass, then
squash merge. Never commit to main directly and never merge on red.
