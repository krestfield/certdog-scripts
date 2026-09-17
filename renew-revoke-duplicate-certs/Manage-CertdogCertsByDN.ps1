<#
.SYNOPSIS
    Searches certdog for valid (non-expired) certificates matching a given subject DN
    (or just the CN component), and either revokes or marks-as-renewed all matches.

.PARAMETER apiUrl
    Base URL to the certdog API, e.g. https://certdog.example.com/certdog/api

.PARAMETER apiToken
    The certdog API bearer token.

.PARAMETER certSubject
    The subject DN to match against, e.g. "CN=test cert,O=Test,C=GB"

.PARAMETER compareCNOnly
    Switch. If provided, only the CN component of $certSubject is matched against
    the CN component of each certificate's DN (rather than the whole DN).

.PARAMETER action
    'renew' or 'revoke'.

.PARAMETER serialNumber
    Optional. A certificate serial number to exclude from processing - any matched
    certificate with this serial number will be skipped (not revoked/renewed).

.EXAMPLE
    .\Manage-CertdogCertsByDn.ps1 -apiUrl "https://certdog.local/certdog/api" `
        -apiToken "eyJhbGciOi..." -certSubject "CN=test cert,O=Test,C=GB" -action revoke

.EXAMPLE
    .\Manage-CertdogCertsByDn.ps1 -apiUrl "https://certdog.local/certdog/api" `
        -apiToken "eyJhbGciOi..." -certSubject "CN=test cert" -compareCNOnly -action renew
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$apiUrl,

    [Parameter(Mandatory = $true)]
    [string]$apiToken,

    [Parameter(Mandatory = $true)]
    [string]$certSubject,

    [switch]$compareCNOnly,

    [Parameter(Mandatory = $true)]
    [ValidateSet('renew', 'revoke')]
    [string]$action,

    [string]$serialNumber
)

$ErrorActionPreference = 'Stop'

# Trim any trailing slash from the API URL so we don't end up with double slashes
$apiUrl = $apiUrl.TrimEnd('/')

$headers = @{
    Authorization  = "Bearer $apiToken"
    'Content-Type' = 'application/json'
}

# --- Build the subjectDn search regex -------------------------------------

function Get-CnValue {
    param([string]$Dn)

    # Matches CN=<value> up to the next unescaped comma, or end of string.
    # Handles DNs where CN is not necessarily the first component.
    $match = [regex]::Match($Dn, '(?i)CN\s*=\s*([^,]+)')
    if (-not $match.Success) {
        throw "Could not find a CN component in subject '$Dn'"
    }
    return $match.Groups[1].Value.Trim()
}

if ($compareCNOnly) {
    $cnValue      = Get-CnValue -Dn $certSubject
    $escapedCn    = [regex]::Escape($cnValue)
    # Match CN=<value> where it's followed by a comma (another RDN) or end of string,
    # so "CN=test cert" doesn't also match "CN=test cert 2"
    $searchRegex  = "(?i)CN=$escapedCn(,|$)"
    $matchLabel   = 'common name'
    $matchDisplay = "CN=$cnValue"
}
else {
    $escapedDn    = [regex]::Escape($certSubject.Trim())
    # Anchored, case-insensitive full-DN match
    $searchRegex  = "(?i)^$escapedDn$"
    $matchLabel   = 'DN'
    $matchDisplay = $certSubject.Trim()
}

# --- Search for matching, currently-valid certificates ---------------------

$validToFrom = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')

$searchBody = @{
    subjectDn   = $searchRegex
    validToFrom = $validToFrom
} | ConvertTo-Json

Write-Verbose "Searching certdog: $apiUrl/certs/search"
Write-Verbose "Search body: $searchBody"

try {
    $searchResponse = Invoke-RestMethod -Uri "$apiUrl/certs/search" -Method Post -Headers $headers -Body $searchBody
}
catch {
    Write-Error "Certificate search failed: $_"
    return
}

# The search API always returns a bare JSON array (possibly empty) of
# { id, subjectDn, serialNumber, renewed, revoked } objects. Invoke-RestMethod
# will hand back $null if the array is empty, and a single PSCustomObject
# (not an array) if there's exactly one match - so wrap in @() to normalise
# to an array.
$certs = @($searchResponse)

# Only process certificates that haven't already been renewed or revoked
$certs = @($certs | Where-Object { $_.renewed -eq $false -and $_.revoked -eq $false })

# Exclude the caller's own/excluded certificate, if a serial number was supplied
if ($serialNumber) {
    $excluded = @($certs | Where-Object { $_.serialNumber -eq $serialNumber })
    $certs    = @($certs | Where-Object { $_.serialNumber -ne $serialNumber })

    foreach ($ex in $excluded) {
        Write-Host "  - Skipping (excluded serial number): id=$($ex.id) serial=$($ex.serialNumber) subject='$($ex.subjectDn)'"
    }
}

$certCount = $certs.Count

if ($certCount -eq 0) {
    Write-Host "No valid, unprocessed certificates found with the same $matchLabel of $matchDisplay."
    return
}

$actionDescription = if ($action -eq 'renew') { 'Marking as renewed' } else { 'Revoking' }
$plural = if ($certCount -eq 1) { '' } else { 's' }

Write-Host "Found $certCount valid certificate$plural with the same $matchLabel of $matchDisplay. $actionDescription."

# --- Act on each matching certificate --------------------------------------

foreach ($cert in $certs) {

    $certId  = $cert.id
    $subject = $cert.subjectDn
    $serial  = $cert.serialNumber

    try {
        if ($action -eq 'renew') {
            $renewBody = @{ renewed = $true } | ConvertTo-Json

            Write-Verbose "PATCH $apiUrl/certs/$certId : $renewBody"
            Invoke-RestMethod -Uri "$apiUrl/certs/$certId" -Method Patch -Headers $headers -Body $renewBody | Out-Null

            Write-Host "  - Marked as renewed: id=$certId serial=$serial subject='$subject'"
        }
        else {
            $revokeBody = @{
                certId = $certId
                reason = 'superceded'
            } | ConvertTo-Json

            Write-Verbose "POST $apiUrl/certs/revoke : $revokeBody"
            Invoke-RestMethod -Uri "$apiUrl/certs/revoke" -Method Post -Headers $headers -Body $revokeBody | Out-Null

            Write-Host "  - Revoked: id=$certId serial=$serial subject='$subject'"
        }
    }
    catch {
        Write-Warning "  - FAILED to process cert id=$certId serial=$serial subject='$subject': $_"
    }
}