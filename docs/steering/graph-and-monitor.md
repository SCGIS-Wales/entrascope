# Microsoft Graph and Azure Monitor

## The discovery model

For every application registration and every service principal, entrascope
projects the attributes that explain a failure:

- **Identity**: object id, application id, display name, creation date.
- **Sign in audience**: single tenant, multi tenant, multi tenant with personal
  accounts, or personal accounts only. A mismatch here is a common cause of
  AADSTS700016 and AADSTS500011.
- **Redirect URIs**, separately for the web, single page application and
  public client platforms, because AADSTS50011 compares byte for byte and is
  sensitive to case and to a trailing slash.
- **Permissions**, both sides of the relationship. Requested, from
  `requiredResourceAccess`. Granted, from the application role assignments and
  the OAuth2 permission grants on the service principal. The difference between
  requested and granted is where missing admin consent shows up.
- **Owners**, because ownership determines what
  `Application.ReadWrite.OwnedBy` can and cannot do.
- **Credentials**: `passwordCredentials` and `keyCredentials`, each with its
  `endDateTime`. Anything inside the warning window is flagged, and anything
  already past is flagged distinctly. This is the answer to AADSTS7000222.
- **Federated identity credentials**, for workload identity federation, with
  issuer, subject and audience.
- **SAML configuration**: `identifierUris`, `replyUrls`, the preferred single
  sign on mode, the claims mapping policy and the signing certificate expiry.
- **Assignment requirement**: `appRoleAssignmentRequired` on the service
  principal, which explains why a correctly consented application still refuses
  a user.

## Application types to cover

Confidential clients using OAuth 2.0 and OpenID Connect. Public clients. Native,
mobile and desktop applications. Single page applications. SAML enterprise
applications, both gallery and non gallery. Managed identities, system and user
assigned, which appear as service principals with the managed identity type.
Workload identity federation applications. Classification is a pure function of
the projected attributes and is tested with one fixture per type.

## The log interrogation model

Seven sources, reachable two ways.

| Source | Graph | Log Analytics table |
| --- | --- | --- |
| Directory audits, category ApplicationManagement | `/auditLogs/directoryAudits` | `AuditLogs` |
| Interactive user sign ins | `/auditLogs/signIns` | `SigninLogs` |
| Non interactive user sign ins | `/auditLogs/signIns` filtered | `AADNonInteractiveUserSignInLogs` |
| Service principal sign ins | `/auditLogs/signIns` filtered | `AADServicePrincipalSignInLogs` |
| Managed identity sign ins | `/auditLogs/signIns` filtered | `AADManagedIdentitySignInLogs` |
| Provisioning | `/auditLogs/provisioning` | `AADProvisioningLogs` |
| Microsoft Graph activity | not available | `MicrosoftGraphActivityLogs` |

Both routes return the same data transfer object, so a caller does not need to
know which one answered. The Graph route works on any tenant with the right
permission. The Log Analytics route needs a diagnostic setting, a workspace and
the Log Analytics Reader role, and gives longer retention and cross source
joins.

Service principal sign ins are the category that shows client credentials flow
failures, which is where most application authentication problems are visible.
Microsoft Graph activity logs are the only place to see which application made
a particular Graph call and what it was granted at the time.

## Entra logs are not in the Azure activity log

Entra directory operations do not appear in the Azure subscription activity
log. They appear in the Entra audit logs. This is stated in the product
document, in the CLI help and here, because it is the most common wrong turn.

## Permissions, roles and licences

Application permissions on Microsoft Graph, resource application id
`00000003-0000-0000-c000-000000000000`:

| Capability | Permission | App role id | Consent |
| --- | --- | --- | --- |
| Read applications and service principals | Application.Read.All | 9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30 | admin |
| Read audit and sign in logs | AuditLog.Read.All | b0afded3-3588-46d8-8b3d-9842eff778da | admin |
| Read directory objects and owners | Directory.Read.All | 7ab1d382-f21e-4acd-a863-ba3e13f7da61 | admin |
| Read tenant policies | Policy.Read.All | 246dd0d5-5bd0-4def-940b-0421030a5b68 | admin |
| Optional and privileged, excluded by default | AppRoleAssignment.ReadWrite.All | 06b708a9-e830-4db3-a914-8e69da51d44f | admin |

Grant and consent:

```bash
APP=<your-app-client-id>
GRAPH=00000003-0000-0000-c000-000000000000
az ad app permission add --id $APP --api $GRAPH \
  --api-permissions \
  9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role \
  b0afded3-3588-46d8-8b3d-9842eff778da=Role \
  7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role \
  246dd0d5-5bd0-4def-940b-0421030a5b68=Role
az ad app permission admin-consent --id $APP
```

`AppRoleAssignment.ReadWrite.All` lets an application grant privileges to
itself, to other applications and to any user. entrascope is read only and
excludes it.

Querying a Log Analytics workspace needs Log Analytics Reader, or Reader, on
the workspace or its resource group:

```bash
az role assignment create --assignee <object-id> \
  --role "Log Analytics Reader" \
  --scope <workspace-resource-id>
```

Licences. Audit logs are available on any tier through Graph. Sign in logs, and
the diagnostic settings that export the sign in categories and Microsoft Graph
activity, need Entra ID P1 or P2. Configuring a diagnostic setting needs the
Security Administrator role. Portal retention is 7 days on Free and 30 days on
P1 or P2, and once logs are routed the workspace retention governs. Licence
gating is tenant specific, so entrascope reports what it observes and links to
the Microsoft guidance rather than asserting entitlement.
