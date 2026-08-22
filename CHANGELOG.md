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
