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

The `network` section carries the forward proxy and certificate trust rules.
The variable names themselves are configuration, so a site with different
conventions can add its own without a code change. See
`credentials-and-security.md` for what they do.

### fields.yaml

Projections from Graph payloads onto data transfer objects. The left hand side
is the DTO field, the right hand side is the Graph property path, dotted for
nested properties. Also the credential expiry warning window in days.

### logging.yaml

Level, format and destination, with per surface overrides for the CLI and both
MCP servers. The context fields attached to every record. The redaction
placeholder, the keys whose values are always replaced, and the regular
expressions that catch bearer tokens and JSON web tokens wherever they appear.

### credentials.yaml

The credential contract: the directory and file name, the required modes as
octal strings, and the exact JSON keys. The three environment variable names.
The authentication source order, which sources are enabled for automatic
resolution, and whether each yields application or delegated access.

Only the credential file source is enabled by default, because the steering
document requires the fallbacks to be gated. Naming a source with `--auth`
selects it whether or not it is enabled, so `az login` followed by
`--auth azure-cli` works with no configuration change.

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

## Where it comes from at run time

Searched in this order:

1. A directory named with `--config-dir`. Required rather than preferred, so a
   typo fails instead of quietly using another, and used as it stands.
2. `ENTRASCOPE_CONFIG_DIR`, the same.
3. `~/.config/entrascope`, the engineer's own. Used when it holds any YAML file
   at all, and **layered over the shipped defaults**.
4. `entrascope/_config` inside the installed package, which the wheel carries
   by mapping the repository `config` directory into it.
5. The repository `config` directory, which is what a development checkout uses.

## Why the engineer's directory is layered

Everything inside a package is replaced when it is upgraded, so an edit made
there is lost without anybody being told. The engineer's directory sits outside
the package and is never touched.

Layering rather than replacing is what makes that workable. A file there holds
only what was changed; every other setting comes from the defaults underneath.
So a release that adds a setting is picked up without anybody doing anything,
and a file written two releases ago keeps working. A mapping is merged key by
key and a list is replaced whole, because half of somebody's list of endpoints
merged with half of ours would be nobody's list.

A directory named explicitly is not layered. Naming one means that one.

`entrascope config export` writes there by default, and `--only` copies a
single file, which is the shape most changes take. `entrascope config path`
says which directory is in force and whether it is the packaged copy, which is
the question somebody has when an edit appears to do nothing. A test asserts
the wheel still carries the defaults, because that mapping is easy to lose in a
packaging change.

## Rules

- A new endpoint means a new entry in `endpoints.yaml`, not a literal.
- A new error code means a new entry in `error-codes.yaml`, and a test asserts
  every entry carries a remediation and a Microsoft Learn URL.
- A new capability means a new entry in `capabilities.yaml`, and the doctor
  command picks it up with no code change.
- Documentation URLs are configuration, because they change.
