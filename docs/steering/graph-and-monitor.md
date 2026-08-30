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
  `requiredResourceAccess`. Granted, from `appRoleAssignments` and
  `oauth2PermissionGrants` on the service principal. The difference between
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
- **Assignments**, from `appRoleAssignedTo` on the service principal: the
  users, security groups and applications allowed to use it, each with the role
  it holds. A group is the usual answer, and where assignment is required an
  identity that is not here is refused however much has been consented.
- **Memberships**, from `memberOf` on the service principal: the groups,
  directory roles and administrative units the application's own identity
  belongs to. Access held through a group is recorded on the group and nowhere
  on the application.

## The four app role and consent collections

Four Graph collections carry authorisation and three of the four hang off the
same object, which makes them easy to confuse. They are not interchangeable and
reading the wrong one reports the wrong objects entirely.

| Collection | Path | What it holds |
| --- | --- | --- |
| Application permissions held | `/servicePrincipals/{id}/appRoleAssignments` | What this application may do to other resources |
| Assignments to this application | `/servicePrincipals/{id}/appRoleAssignedTo` | Which users, groups and applications may use this one |
| Delegated consent | `/oauth2PermissionGrants?$filter=clientId eq '{id}'` | What was consented on a signed in person's behalf, and by whom |
| Memberships | `/servicePrincipals/{id}/memberOf` | The groups and roles this application's identity belongs to |

Delegated consent is the one that decides whether a permission works for
everybody or for one person. `consentType` is `AllPrincipals` where an
administrator recorded it for the tenant and `Principal` where one person
recorded it for themselves, and in the second case `principalId` names them.
An application permission has no such distinction: there is no way to hold one
without an administrator having consented, so holding one is itself the record.

Whether a delegated scope needs an administrator at all is decided by the
resource, not by the client: `oauth2PermissionScopes[].type` is `Admin` where
only an administrator may consent and `User` where the signed in person may
consent for themselves. Reporting a `User` scope as an admin consent problem
sends the engineer to the wrong place, so the two are kept apart.

A tenant wide sweep reads delegated consent once for the whole directory and
matches it up by `clientId`, because one paged call answers for every
application and asking per application is a call each.

## Application types to cover

Two rules the classification follows, both learned by creating one application
of each kind in a real tenant and reading them back.

An application that exposes an API and registers no redirect URI is a resource,
not a client. Calling it a public client, which the fallback used to do, sends
the reader looking for a sign in that never happens.

A confidential client is one that holds a credential. A web application without
one is a client all the same, but calling it confidential says it holds a
secret it does not have.

A service principal is the instance, not the definition. Whether the
application behind it is confidential, public or a single page application is
decided by its registration, which the service principal does not carry, so
anything beyond the kinds a service principal genuinely determines, which are
managed identity, legacy and the SAML modes, is named for what it is.



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
