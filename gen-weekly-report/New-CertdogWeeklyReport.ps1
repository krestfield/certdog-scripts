<#
.SYNOPSIS
    Generates a weekly Certdog certificate issuance report as a formatted Excel workbook.

.DESCRIPTION
    Queries the Certdog REST API (/certs/search) for certificates issued within the last
    N days, and produces a single-sheet Excel report ("Summary") containing:
      - A headline ("In the last X days, Y certificates have been issued")
      - A small report-info block (generated time, period start/end, count)
      - The full certificate listing (all fields below), sorted by validFrom, as a
        formatted table with conditional formatting on status

    Fields included per certificate: CommonName, SubjectDn, IssuerDn, SerialNumber,
    OwnerUsername, SubjectAlternativeNames, ValidFrom/ValidFromStr, ValidTo/ValidToStr,
    Status, TeamId, KeyUsages.

    Requires the ImportExcel PowerShell module (installed automatically if missing).
    No Excel installation is required - the report is generated headlessly.

.PARAMETER apiUrl
    Base URL of the Certdog REST API, e.g. https://ca3.unsungltd.com/certdog/api

.PARAMETER apiToken
    A valid Certdog API bearer token (see the certdog admin/currentuser API token endpoints)

.PARAMETER numDays
    Number of previous days to include in the report, based on certificate validFrom date

.PARAMETER reportFolder
    Folder where the generated report will be saved. Created automatically if it doesn't exist.

.EXAMPLE
    .\New-CertdogWeeklyReport.ps1 -apiUrl "https://ca3.unsungltd.com/certdog/api" `
        -apiToken $env:CERTDOG_API_TOKEN -numDays 7 -reportFolder "C:\reports"

.NOTES
    The apiToken should be supplied securely by the caller (e.g. from a secrets manager,
    Windows Credential Manager, or a CI/CD secret) rather than hardcoded - see the calling
    script/scheduled task for how the token is sourced.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$apiUrl,

    [Parameter(Mandatory)]
    [string]$apiToken,

    [Parameter(Mandatory)]
    [int]$numDays,

    [Parameter(Mandatory)]
    [string]$reportFolder
)

$ErrorActionPreference = 'Stop'

#region Setup

function Confirm-ImportExcelModule {
    if (Get-Module -ListAvailable -Name ImportExcel) {
        Import-Module ImportExcel -ErrorAction Stop
        return
    }

    Write-Verbose "ImportExcel module not found - attempting to install for current user..."

    try {
        # Force TLS 1.2 - older PowerShell/.NET defaults can fail to negotiate with the
        # PowerShell Gallery otherwise
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        Install-Module ImportExcel -Scope CurrentUser -Force -ErrorAction Stop
        Import-Module ImportExcel -ErrorAction Stop
    }
    catch {
        throw @"
Could not automatically install/load the required 'ImportExcel' PowerShell module.

This is often caused by an outdated or broken 'PowerShellGet' module on Windows
PowerShell 5.1. To fix it, run the following ONCE in an elevated PowerShell
session, close the window, then re-run this script in a NEW session:

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser
    Install-Module -Name PowerShellGet -Force -AllowClobber -Scope CurrentUser
    Install-Module ImportExcel -Scope CurrentUser -Force

Original error: $($_.Exception.Message)
"@
    }
}

Confirm-ImportExcelModule

if (-not (Test-Path -Path $reportFolder)) {
    Write-Verbose "Report folder '$reportFolder' does not exist - creating it."
    New-Item -Path $reportFolder -ItemType Directory -Force | Out-Null
}

#endregion

#region Fetch data from Certdog

$sinceDate = (Get-Date).Date.AddDays(-$numDays)
$untilDate = Get-Date

Write-Verbose "Querying Certdog for certificates issued between $sinceDate and $untilDate"

$searchBody = @{
    validFromFrom = $sinceDate.ToString("o")
    validFromTo   = $untilDate.ToString("o")
    certsPerPage  = 5000   # generous cap - raise if a single report period can exceed this
} | ConvertTo-Json

$headers = @{
    Authorization = "Bearer $apiToken"
}

try {
    $certs = Invoke-RestMethod -Uri "$($apiUrl.TrimEnd('/'))/certs/search" -Method Post `
        -Body $searchBody -ContentType "application/json" -Headers $headers
}
catch {
    throw "Failed to query Certdog API at '$apiUrl/certs/search': $($_.Exception.Message)"
}

if (-not $certs) {
    $certs = @()
}

$numCerts = @($certs).Count
Write-Verbose "Retrieved $numCerts certificate(s) from Certdog."

#endregion

#region Shape data for the report

$reportData = @($certs) | ForEach-Object {
    $validFromDate = $null
    if ($_.validFrom) { $validFromDate = [datetime]$_.validFrom }

    [PSCustomObject]@{
        CommonName              = $_.commonName
        SubjectDn                = $_.subjectDn
        IssuerDn                  = $_.issuerDn
        SerialNumber             = $_.serialNumber
        OwnerUsername             = $_.ownerUsername
        SubjectAlternativeNames  = ($_.subjectAlternativeNames -join '; ')
        ValidFrom                 = $validFromDate
        ValidFromStr              = if ($validFromDate) { $validFromDate.ToString('dd MMM yyyy') } else { $_.validFromStr }
        ValidTo                   = if ($_.validTo) { [datetime]$_.validTo } else { $null }
        ValidToStr                = $_.validToStr
        Status                    = $_.status
        TeamId                    = $_.teamId
        KeyUsages                 = ($_.keyUsages -join '; ')
    }
} | Sort-Object ValidFrom

#endregion

#region Build the Excel report

$timestamp = Get-Date -Format 'yyyy-MM-dd'
$reportPath = Join-Path -Path $reportFolder -ChildPath "CertdogWeeklyReport_$timestamp.xlsx"

if (Test-Path $reportPath) {
    Remove-Item $reportPath -Force
}

$summaryHeadline = "In the last $numDays days, $numCerts certificates have been issued"

Write-Verbose $summaryHeadline

# --- Summary sheet: headline + report info, then the FULL certificate listing ---
$summaryInfo = [PSCustomObject]@{
    'Report Generated'    = (Get-Date -Format 'dd MMM yyyy HH:mm')
    'Period Start'        = $sinceDate.ToString('dd MMM yyyy')
    'Period End'          = $untilDate.ToString('dd MMM yyyy')
    'Certificates Issued' = $numCerts
}

# Info block starts at row 3, leaving room for the headline (row 1) + a blank row (row 2)
$excelPkg = $summaryInfo | Export-Excel -Path $reportPath -WorksheetName "Summary" `
    -StartRow 3 -AutoSize -PassThru

$summarySheet = $excelPkg.Workbook.Worksheets["Summary"]
$summarySheet.Cells[1, 1].Value = $summaryHeadline
$summarySheet.Cells[1, 1].Style.Font.Size = 16
$summarySheet.Cells[1, 1].Style.Font.Bold = $true

# Full certificate listing, all fields, ordered by validFrom - placed below the info block
$detailStartRow = 6

if ($reportData.Count -gt 0) {
    $excelPkg = $reportData | Export-Excel -ExcelPackage $excelPkg -WorksheetName "Summary" `
        -StartRow $detailStartRow -AutoSize -FreezeTopRow -BoldTopRow `
        -TableName "AllCertificates" -TableStyle Medium9 `
        -ConditionalText @(
            New-ConditionalText -Text "Revoked" -ConditionalTextColor DarkRed -BackgroundColor LightPink
            New-ConditionalText -Text "Valid" -ConditionalTextColor DarkGreen -BackgroundColor LightGreen
        ) -PassThru
}

Close-ExcelPackage $excelPkg

#endregion

Write-Output $summaryHeadline
Write-Output "Report saved to: $reportPath"

# Return the path so the calling script (e.g. one that emails the report) can pick it up
return $reportPath
