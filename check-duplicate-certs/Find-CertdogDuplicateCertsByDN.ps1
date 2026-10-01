<#
.SYNOPSIS
    Searches certdog for valid (non-expired) certificates matching a given subject DN
    (or just the CN component) and returns the number of matching certificates found.

.DESCRIPTION
    Intended to be used as an approval step in a certdog workflow:
      - Returns (exits with) 0 if no matching certificates are found, allowing the
        request to proceed
      - Returns (exits with) the number of matching certificates found (> 0) if any
        exist, stopping the request
      - Returns (exits with) -1 if the check could not be completed (e.g. bad
        parameters or the API call failed), also stopping the request

    Certificates that have already been marked as renewed or revoked are ignored.

    All output is written with Write-Host so that it is captured in the certdog logs.

    Requires the certdog PowerShell module (certdog-module.psm1) to be in the current
    directory.

.PARAMETER apiUrl
    Optional. Base URL to the certdog API, e.g. https://certdog.example.com/certdog/api
    If not provided, the certdog module determines the URL itself (from apiurl.conf
    or the registry).

.PARAMETER apiToken
    The certdog API bearer token.

.PARAMETER certSubject
    The subject DN to match against, e.g. "CN=test cert,O=Test,C=GB"

.PARAMETER compareCNOnly
    Switch. If provided, only the CN component of $certSubject is matched against
    the CN component of each certificate's DN (rather than the whole DN).
    Cannot be combined with -ignoreRdnOrder.

.PARAMETER ignoreRdnOrder
    Switch. If provided, a certificate's DN matches when it has the same components
    (RDNs) with the same values as $certSubject, in any order. For example
    "CN=a,O=b,OU=c,C=GB" matches "CN=a,OU=c,O=b,C=GB". Comparison is case-insensitive
    and ignores spaces around separators. Cannot be combined with -compareCNOnly.

.PARAMETER serialNumber
    Optional. A certificate serial number to exclude from the check - any matched
    certificate with this serial number will not be counted.

.EXAMPLE
    .\Find-CertdogDuplicateCertsByDN.ps1 -apiUrl "https://certdog.local/certdog/api" `
        -apiToken "eyJhbGciOi..." -certSubject "CN=test cert,O=Test,C=GB"

.EXAMPLE
    .\Find-CertdogDuplicateCertsByDN.ps1 -apiToken "eyJhbGciOi..." -certSubject "CN=test cert" -compareCNOnly

.EXAMPLE
    .\Find-CertdogDuplicateCertsByDN.ps1 -apiUrl "https://certdog.local/certdog/api" `
        -apiToken "eyJhbGciOi..." -certSubject "CN=test cert,O=Test,OU=Dev,C=GB" -ignoreRdnOrder
#>

[CmdletBinding()]
param(
    [string]$apiUrl,

    [Parameter(Mandatory = $true)]
    [string]$apiToken,

    [Parameter(Mandatory = $true)]
    [string]$certSubject,

    [switch]$compareCNOnly,

    [switch]$ignoreRdnOrder,

    [string]$serialNumber
)

$ErrorActionPreference = 'Stop'

# Exit code used when the check cannot be completed. Non-zero so the workflow stops.
$errorExitCode = -1

if ($compareCNOnly -and $ignoreRdnOrder) {
    Write-Host "ERROR: -compareCNOnly and -ignoreRdnOrder cannot be used together"
    exit $errorExitCode
}

try {
    Import-Module .\certdog-module.psm1
}
catch {
    Write-Host "ERROR: Unable to load certdog-module.psm1: $($_.Exception.Message)"
    exit $errorExitCode
}

# Only override the API URL if one was supplied - otherwise the module works it out
if ($apiUrl) {
    # Trim any trailing slash from the API URL so we don't end up with double slashes
    Set-ApiUrl -url $apiUrl.TrimEnd('/')
}
Set-ApiToken -authToken $apiToken

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

function Get-DnRdns {
    param([string]$Dn)

    # Split on commas (and '+' for multi-valued RDNs) that aren't escaped with a backslash
    foreach ($part in ($Dn -split '(?<!\\)[,+]')) {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }

        $pair = $part -split '(?<!\\)=', 2
        if ($pair.Count -ne 2) {
            throw "Could not parse component '$part' in subject '$Dn'"
        }
        [pscustomobject]@{
            Type  = $pair[0].Trim().ToUpperInvariant()
            Value = $pair[1].Trim()
        }
    }
}

function Get-NormalisedDn {
    param([string]$Dn)

    # Upper-case and sort the components so DNs with the same RDNs in a different
    # order (or different case/spacing) produce the same string
    $rdns = @(Get-DnRdns -Dn $Dn | ForEach-Object { "$($_.Type)=$($_.Value.ToUpperInvariant())" })
    return ($rdns | Sort-Object) -join ','
}

try {
    if ($compareCNOnly) {
        $cnValue      = Get-CnValue -Dn $certSubject
        $escapedCn    = [regex]::Escape($cnValue)
        # Match CN=<value> where it's followed by a comma (another RDN) or end of string,
        # so "CN=test cert" doesn't also match "CN=test cert 2"
        $searchRegex  = "(?i)CN=$escapedCn(,|$)"
        $matchLabel   = 'common name'
        $matchDisplay = "CN=$cnValue"
    }
    elseif ($ignoreRdnOrder) {
        $targetRdns = @(Get-DnRdns -Dn $certSubject)
        if ($targetRdns.Count -eq 0) {
            throw "Could not find any components in subject '$certSubject'"
        }

        # The API search only takes a regex, which can't practically express "these RDNs in
        # any order". So search on a single component (the CN if there is one) and then
        # compare the full DNs once the results come back.
        $anchor = $targetRdns | Where-Object { $_.Type -eq 'CN' } | Select-Object -First 1
        if (-not $anchor) {
            $anchor = $targetRdns[0]
        }
        $escapedType  = [regex]::Escape($anchor.Type)
        $escapedValue = [regex]::Escape($anchor.Value)
        $searchRegex  = "(?i)(^|[,+])\s*$escapedType\s*=\s*$escapedValue\s*([,+]|$)"

        $normalisedSubject = Get-NormalisedDn -Dn $certSubject
        $matchLabel   = 'DN (in any RDN order)'
        $matchDisplay = $certSubject.Trim()
    }
    else {
        $escapedDn    = [regex]::Escape($certSubject.Trim())
        # Anchored, case-insensitive full-DN match
        $searchRegex  = "(?i)^$escapedDn$"
        $matchLabel   = 'DN'
        $matchDisplay = $certSubject.Trim()
    }
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit $errorExitCode
}

# --- Search for matching, currently-valid certificates ---------------------

$validToFrom = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')

Write-Host "Checking certdog for valid certificates with the same $matchLabel of $matchDisplay"

try {
    $searchResponse = Search-Certs -subjectDn $searchRegex -validToFrom $validToFrom
}
catch {
    Write-Host "ERROR: Certificate search failed: $($_.Exception.Message)"
    exit $errorExitCode
}

# The search API returns a bare JSON array (possibly empty). Search-Certs
# will hand back $null if the array is empty, and a single PSCustomObject
# (not an array) if there's exactly one match - so wrap in @() to normalise
# to an array.
$certs = @($searchResponse)

# Only count certificates that haven't already been renewed or revoked
$certs = @($certs | Where-Object { $_.renewed -eq $false -and $_.revoked -eq $false })

# The search only matched on one component, so keep just the certificates whose
# DN has exactly the same RDNs as the requested subject
if ($ignoreRdnOrder) {
    $certs = @($certs | Where-Object {
        $cert = $_
        try {
            (Get-NormalisedDn -Dn $cert.subjectDn) -eq $normalisedSubject
        }
        catch {
            Write-Host "Skipping cert id=$($cert.id): $($_.Exception.Message)"
            $false
        }
    })
}

# Exclude the caller's own/excluded certificate, if a serial number was supplied
if ($serialNumber) {
    $excluded = @($certs | Where-Object { $_.serialNumber -eq $serialNumber })
    $certs    = @($certs | Where-Object { $_.serialNumber -ne $serialNumber })

    foreach ($ex in $excluded) {
        Write-Host "  - Ignoring (excluded serial number): serial=$($ex.serialNumber) subject='$($ex.subjectDn)'"
    }
}

$certCount = $certs.Count

if ($certCount -eq 0) {
    Write-Host "No valid certificates found with the same $matchLabel of $matchDisplay. Returning 0"
    exit 0
}

$plural = if ($certCount -eq 1) { '' } else { 's' }

Write-Host "Found $certCount matching cert$plural with the same $matchLabel of $matchDisplay"
Write-Host "Serial Number, DN, Issuer DN, Valid To"

foreach ($cert in $certs) {
    $validTo = if ($cert.validToStr) { $cert.validToStr } else { $cert.validTo }
    Write-Host "$($cert.serialNumber), $($cert.subjectDn), $($cert.issuerDn), $validTo"
}

Write-Host "Returning $certCount"
exit $certCount