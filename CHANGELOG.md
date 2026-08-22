# Changelog

All notable changes to this project are documented in this file.

The format follows Keep a Changelog, and this project adheres to semantic
versioning.

## [Unreleased]

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
