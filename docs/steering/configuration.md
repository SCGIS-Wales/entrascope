# Configuration

Every endpoint, table name, KQL fragment, retry value, field mapping, error
code and documentation URL lives in `config/`. Code reads configuration and
never hardcodes. A guard test enforces this by parsing every module and
rejecting string literals that look like a URL or a known table name.

`entrascope.config` is the only module that opens a YAML file. Everything else
takes configuration as an argument or asks the cached accessor for it. Each
file is validated against a Pydantic schema at load time, so a malformed file
fails immediately with a readable message rather than at the point of use.

## The files

### endpoints.yaml

The Microsoft Graph base URL, API version, default scope and the resource
application id for Graph. Every Graph path used by the tool, as a template with
named placeholders. The Azure Resource Manager base URL and the diagnostic
settings path. The authority templates for both token versions: issuer, token
endpoint, authorize endpoint, JWKS URI and OpenID Connect discovery, each
carrying a `{tenant_id}` placeholder. The well known path for protected
resource metadata.

### tables.yaml

The seven Entra diagnostic setting categories, each mapped to the Log Analytics
table it populates, the minimum licence tier it needs and a description. The
audit category constant for application management.

### retry.yaml

Connect and read timeouts, the user agent template, connection pool sizes. The
urllib3 retry policy: totals per class, backoff factor and ceiling, whether to
respect `Retry-After`, the status forcelist and the allowed methods. The
thread pool worker count. Paging page size and a page ceiling.

### fields.yaml

Projections from Graph payloads onto data transfer objects. The left hand side
is the DTO field, the right hand side is the Graph property path, dotted for
nested properties. Also the credential expiry warning window in days.

### logging.yaml

Level, format and destination, with per surface overrides for the CLI and both
MCP servers. The context fields attached to every record. The redaction
placeholder, the keys whose values are always replaced, and the regular
expressions that catch bearer tokens and JSON web tokens wherever they appear.

### error-codes.yaml

A default entry for unrecognised codes, then one entry per known code carrying
meaning, likely cause, remediation and a Microsoft Learn URL. Beyond the AADSTS
codes it also covers the permission traps: the difference between
`Application.ReadWrite.OwnedBy` and `Application.ReadWrite.All`, the tenant
setting that stops users registering applications, restricted management
administrative units, and permissions added but never consented.

### capabilities.yaml

The four required Graph application permissions with their app role identifiers
and the privileged one that is excluded by default. The directory roles that
suffice when the active authentication source is delegated. The capability
list, each entry naming its prerequisite, its remediation and its documentation
URL, which is what the doctor command renders. The service plan identifiers
that indicate the Entra ID tier.

### kql/

One file per query template, parameterised with named placeholders. Queries are
never assembled by concatenation in code.

## Rules

- A new endpoint means a new entry in `endpoints.yaml`, not a literal.
- A new error code means a new entry in `error-codes.yaml`, and a test asserts
  every entry carries a remediation and a Microsoft Learn URL.
- A new capability means a new entry in `capabilities.yaml`, and the doctor
  command picks it up with no code change.
- Documentation URLs are configuration, because they change.
