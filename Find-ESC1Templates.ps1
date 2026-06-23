<#
.SYNOPSIS
    Enumerates AD CS certificate templates vulnerable to ESC1 using certutil.

.DESCRIPTION
    Parses certutil -v -template output to find templates matching ESC1 conditions:
      - Client Authentication EKU (1.3.6.1.5.5.7.3.2)
      - CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (Supply in Request)
      - Enrollment rights for Domain Users / Authenticated Users / Everyone

    Any domain user can run this — no special privileges required.

.EXAMPLE
    .\Find-ESC1Templates.ps1
#>

$templates = certutil -v -template | Out-String

$templateBlocks = $templates -split "Template\["

foreach ($block in $templateBlocks) {

    if ($block -match "TemplatePropCommonName = (.+)") {
        $templateName = $matches[1].Trim()
    } else {
        continue
    }

    $hasClientAuth = $block -match "1\.3\.6\.1\.5\.5\.7\.3\.2"

    $hasSupplySubject = $block -match "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT"

    $hasManagerApproval = $block -match "CT_FLAG_PEND_ALL_REQUESTS"
    $authSigMatch = $block -match "szOID_NTDS_CA_SECURITY_EXT -- (\d+)"
    $authSigCount = if ($authSigMatch) { [int]$matches[1] } else { 0 }

    $enrollAuthUsers = $block -match "Allow Enroll.*Authenticated Users"
    $enrollDomainUsers = $block -match "Allow Enroll.*Domain Users"
    $enrollEveryone = $block -match "Allow Enroll.*Everyone"
    $hasEnrollPermissions = $enrollAuthUsers -or $enrollDomainUsers -or $enrollEveryone

    if ($hasClientAuth -and $hasSupplySubject -and $hasEnrollPermissions -and (-not $hasManagerApproval) -and ($authSigCount -eq 0)) {
        $enrollees = @()
        if ($enrollDomainUsers) { $enrollees += "Domain Users" }
        if ($enrollAuthUsers) { $enrollees += "Authenticated Users" }
        if ($enrollEveryone) { $enrollees += "Everyone" }

        Write-Output "[!] VULNERABLE: $templateName"
        Write-Output "    - Client Authentication EKU Found"
        Write-Output "    - Enrollee Supplies Subject Found"
        Write-Output "    - Manager Approval: No"
        Write-Output "    - Authorized Signatures: 0"
        Write-Output "    - Enrollable By: $($enrollees -join ', ')"
        Write-Output ""
    }
}
