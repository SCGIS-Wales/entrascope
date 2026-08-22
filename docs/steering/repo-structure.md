# Repository structure

```
entrascope/
  CLAUDE.md
  README.md
  LICENSE
  CHANGELOG.md
  pyproject.toml
  .pre-commit-config.yaml
  .gitignore
  Dockerfile                      # phase 8
  docs/
    steering/
      product.md
      tech-stack.md
      repo-structure.md
      coding-standards.md
      configuration.md
      credentials-and-security.md
      graph-and-monitor.md
      mcp-server.md
      testing-strategy.md
      release-and-publishing.md
      tasks.md
  config/
    endpoints.yaml
    tables.yaml
    error-codes.yaml
    capabilities.yaml
    retry.yaml
    fields.yaml
    logging.yaml
    kql/
      signins_failures.kql
      audit_applicationmanagement.kql
      graph_activity.kql
  src/
    entrascope/
      __init__.py
      __main__.py
      cli.py            # click groups and commands
      config.py         # the only module that reads YAML
      logger.py         # the only logger factory
      redaction.py      # secret redaction, applied as a logging filter
      credentials.py    # credential file, permissions, authentication sources
      http.py           # the only module that imports requests
      graph.py          # Microsoft Graph calls
      monitor.py        # Azure Monitor log queries
      discovery.py      # application and service principal projection
      logs.py           # log interrogation
      errors.py         # error code to remediation
      capabilities.py   # capability detection
      doctor.py         # preflight checks
      models.py         # immutable data transfer objects
      render.py         # tables, json, yaml, exit codes
      mcp_tools.py      # the shared MCP tool surface
      mcp_stdio.py      # local stdio server
      mcp_http.py       # remote Streamable HTTP server
  tests/
    conftest.py
    fixtures/
    test_guards.py
    test_config.py
    test_credentials.py
    test_graph.py
    test_monitor.py
    test_discovery.py
    test_logs.py
    test_errors.py
    test_doctor.py
    test_cli.py
    test_mcp_tools.py
    test_mcp_http_auth.py
  .github/
    dependabot.yml
    workflows/
      ci.yml
      codeql.yml
```

Three modules are additions to the original steering tree, each for a reason:

- `logger.py`, so that redaction and the correlation id are structural rather
  than remembered at each call site.
- `http.py`, so that there is one session factory and one retry policy.
- `render.py`, so that an MCP tool result and a CLI `--output json` payload are
  the same bytes rather than two implementations that drift.
