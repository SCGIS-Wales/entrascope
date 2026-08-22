# Technology stack

Python 3.14, standard build with the global interpreter lock. The free
threaded build is not required and is not supported.

## Runtime dependencies

| Package | Purpose |
| --- | --- |
| click | command groups, subcommands, the console entry point |
| requests | every outbound HTTP call, through `entrascope.http` |
| urllib3 | retry and backoff policy mounted on the requests adapter |
| azure-identity | token acquisition, including the Azure CLI credential |
| azure-monitor-query | Log Analytics queries through `LogsQueryClient` |
| fastmcp | the MCP server framework for both the stdio and HTTP surfaces |
| pyjwt with the crypto extra | token inspection in doctor, and bespoke validation |
| pyyaml | configuration loading |
| rich | table rendering |
| pydantic | schema validation of configuration and of MCP tool output |

Development adds pytest, pytest-cov, pytest-asyncio, pytest-timeout, responses,
ruff and mypy.

## Decisions and their justification

### Microsoft Graph over requests, not msgraph-sdk

Direct calls against the Graph REST endpoints defined in
`config/endpoints.yaml`. msgraph-sdk is a large, class heavy, fluent API
dependency that conflicts with the functional only rule and pulls a wide
dependency tree. Direct HTTP keeps the code functional, keeps every endpoint in
YAML, and makes mocking trivial. If generated models are ever wanted,
msgraph-core may be added and documented as a framework contract exception.

### requests, not httpx

azure-core, which azure-identity and azure-monitor-query both sit on, declares
requests as a hard dependency and uses it as its default synchronous transport.
requests is therefore already in the tree. Using it for the Graph calls as well
gives one HTTP stack, one connection pool configuration, one proxy and TLS
story, one set of environment variables, and one mocking library across every
outbound call. Choosing httpx would have meant carrying two.

Four consequences follow, and all of them are deliberate:

1. The codebase is synchronous. requests has no async interface, so every
   Graph and Monitor function is a plain `def`. FastMCP accepts synchronous
   tool functions, so the MCP surface is unaffected.
2. Concurrency is threads. Discovery over a large tenant is hundreds of Graph
   calls, so `concurrent.futures.ThreadPoolExecutor` with `max_workers` from
   `config/retry.yaml`, one session per worker, which is the thread safety
   boundary requests documents. The workload is entirely IO bound, so threads
   fit.
3. Retry and backoff live in the transport. `urllib3.util.Retry` mounted on an
   `HTTPAdapter` handles the 429 and 5xx classes, honours `Retry-After` and
   applies exponential backoff, configured declaratively. Only the paging
   interaction with `@odata.nextLink` stays in our own code.
4. Mocking is `responses`, which also intercepts the calls azure-core makes.

httpx remains in the resolved environment because fastmcp and mcp depend on it.
It is imported nowhere in `src/`, and a guard enforces that.

### PyJWT, not python-jose

PyJWT ships a caching JWKS client, is lighter, and is more actively maintained.
FastMCP's `AzureJWTVerifier` already handles JWKS for the server path, so PyJWT
covers token inspection in the doctor command and any bespoke validation.

### Framework contract exceptions

FastMCP providers, `requests.Session`, `HTTPAdapter`, the JSON logging
formatter and Pydantic schema models are all classes. Each is instantiated or
subclassed inside a factory function carrying a comment that begins
`# framework contract:`. Business logic stays in free functions. A guard test
fails the build on any class without that comment.
