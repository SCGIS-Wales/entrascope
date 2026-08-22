# Product

## Purpose

entrascope diagnoses Microsoft Entra ID and Azure application authentication
and authorisation failures. When an application registration stops working, a
client credentials flow returns an AADSTS code, or a consent grant does not
behave as expected, entrascope tells the engineer what happened, why, and what
to change.

## Users

Platform engineers and identity administrators who own application
registrations and enterprise applications, and who need an answer faster than
the portal gives one.

## Capabilities

1. **Discovery.** Enumerate every application registration and every
   enterprise application, of every type, and project the attributes that
   matter to a failure: sign in audience, redirect URIs, requested and granted
   permissions, owners, credentials and their expiry, federated identity
   credentials, SAML configuration and the assignment requirement.
2. **Log interrogation.** Read Entra audit logs, interactive and non
   interactive user sign ins, service principal and managed identity sign ins,
   Microsoft Graph activity and provisioning logs, through Microsoft Graph and
   through Azure Monitor.
3. **Capability detection.** Tell the engineer when the logging they need is
   not switched on, which licence tier it requires, which role enables it, and
   the exact page that explains how.
4. **Error explanation.** Map AADSTS and Microsoft Graph error codes to
   meaning, likely cause, remediation and a documentation link.

## A fact that shapes the product

Entra directory operations do not appear in the Azure subscription activity
log. Engineers look there first and find nothing, and conclude that nothing was
recorded. Application registration changes are recorded in the Entra audit
logs, under the category ApplicationManagement, reachable through Microsoft
Graph and, once a diagnostic setting routes them, through a Log Analytics
workspace. entrascope states this in its help text, in its output and here,
because it is the single most common wrong turn in this diagnosis.

## The investigation model

Discovery, log interrogation and error explanation each answer a question. The
investigation asks them, in the order an engineer would, and turns the answers
into findings ranked by severity:

- **error**, something is already broken,
- **warning**, something will break,
- **note**, context that explains a result.

Scope is either one application or the whole tenant, and the same rules apply
to both. An engineer who knows something is wrong but not where starts with the
tenant. An engineer with an application id starts with that.

The rules cover expired and expiring credentials, failed directory operations
grouped by what was attempted, failed sign ins grouped by error code and
explained, disabled enterprise applications, assignment requirements, insecure
redirect URIs and applications with no owner. Every threshold and every piece
of wording is configuration, so a site can tighten a rule without a code
change.

Microsoft first party enterprise applications are excluded by default. A tenant
carries hundreds of them, they are Microsoft's to manage, and reporting on them
buries the findings that are actually yours.

## Terminology

One thing has one name, in the code, the help text and the documentation:

| Term | Meaning |
| --- | --- |
| application registration | what you register in Entra, the definition |
| enterprise application | the service principal, the instance in a tenant |
| delegated permission | acts as a signed in person, a `scp` claim |
| application permission | acts as itself, a `roles` claim |

The application selector is `--app` everywhere, and everywhere it accepts an
application id, an object id or part of a display name, because an engineer has
whichever of those the error message gave them.

## Surfaces

The same core functions are exposed three ways, so that the answer is identical
whoever asks:

- a command line tool for an engineer at a terminal,
- a local MCP server over stdio for an assistant running on the engineer's
  machine,
- a remote MCP server over Streamable HTTP, protected as an OAuth 2.1 resource
  server validating Entra issued tokens.

## Non goals

entrascope reads. It never writes to the directory, never grants consent, never
rotates a credential and never changes a diagnostic setting. It tells you the
command that would.
