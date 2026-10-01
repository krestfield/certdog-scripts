<#
.SYNOPSIS
    Searches certdog for valid (non-expired) certificates matching a given subject DN
    (or just the CN component), and either revokes or marks-as-renewed all matches.

.PARAMETER apiUrl
    Base URL to the certdog API, e.g. https://certdog.example.com/certdog/api

.PARAMETER apiTokenFilename
    Path to a file containing the certdog API bearer token, encrypted with DPAPI
    (as produced by ConvertFrom-SecureString). The file must have been created by
    the same account, on the same machine, that runs this script. 
    To create it under the LOCAL_SYSTEM account, from an Admin PowerShell/CMD run:
        psexec -s -i powershell.exe 
    Then in the new window run to create a directory:    
        $dir = 'C:\certdog\credentials'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Then set the API key:    
        Read-Host -AsSecureString -Prompt 'API key' | ConvertFrom-SecureString | Set-Content "$dir\apikey.enc"
    You will be prompted to enter the key
    Additionally, protect this file further:
        icacls $dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F'

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

.PARAMETER action
    'renew' or 'revoke'.

.PARAMETER serialNumber
    Optional. A certificate serial number to exclude from processing - any matched
    certificate with this serial number will be skipped (not revoked/renewed).

.EXAMPLE
    .\Manage-CertdogCertsByDn.ps1 -apiUrl "https://certdog.local/certdog/api" `
        -apiTokenFilename "C:\ProgramData\Certdog\apitoken.enc" -certSubject "CN=test cert,O=Test,C=GB" -action revoke

.EXAMPLE
    .\Manage-CertdogCertsByDn.ps1 -apiUrl "https://certdog.local/certdog/api" `
        -apiTokenFilename "C:\ProgramData\Certdog\apitoken.enc" -certSubject "CN=test cert" -compareCNOnly -action renew

.EXAMPLE
    .\Manage-CertdogCertsByDn.ps1 -apiUrl "https://certdog.local/certdog/api" `
        -apiTokenFilename "C:\ProgramData\Certdog\apitoken.enc" -certSubject "CN=test cert,O=Test,OU=Dev,C=GB" -ignoreRdnOrder -action revoke
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$apiUrl,

    [Parameter(Mandatory = $true)]
    [string]$apiTokenFilename,

    [Parameter(Mandatory = $true)]
    [string]$certSubject,

    [switch]$compareCNOnly,

    [switch]$ignoreRdnOrder,

    [Parameter(Mandatory = $true)]
    [ValidateSet('renew', 'revoke')]
    [string]$action,

    [string]$serialNumber
)

$ErrorActionPreference = 'Stop'

if ($compareCNOnly -and $ignoreRdnOrder) {
    throw "-compareCNOnly and -ignoreRdnOrder cannot be used together"
}

# Trim any trailing slash from the API URL so we don't end up with double slashes
$apiUrl = $apiUrl.TrimEnd('/')

# Read and decrypt the DPAPI-protected API token
try {
    $secure = Get-Content -Path $apiTokenFilename | ConvertTo-SecureString
    $apiToken = [System.Net.NetworkCredential]::new('', $secure).Password
}
catch {
    throw "Unable to read the API token from '$apiTokenFilename'. Check the file exists and was created by this account on this machine. Details: $($_.Exception.Message)"
}

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

# The search only matched on one component, so keep just the certificates whose
# DN has exactly the same RDNs as the requested subject
if ($ignoreRdnOrder) {
    $certs = @($certs | Where-Object {
        $cert = $_
        try {
            (Get-NormalisedDn -Dn $cert.subjectDn) -eq $normalisedSubject
        }
        catch {
            Write-Verbose "Skipping cert id=$($cert.id): $($_.Exception.Message)"
            $false
        }
    })
}

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