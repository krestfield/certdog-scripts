<#
.SYNOPSIS
    Validates that all DNS SANs in a PKCS#10 CSR are registered in DNS.

.DESCRIPTION
    Accepts a base64-encoded CSR (with or without PEM headers), extracts all
    DNS Subject Alternative Names, and resolves each via DNS. Returns 0 if all
    SANs resolve successfully, or 1 if any SAN cannot be found. Results are
    written to the console.

    Lookups are DNS-only: the hosts file, LLMNR and NetBIOS are not used, and
    a name only counts as registered if DNS returns at least one answer record.

    By default any name that resolves passes - including public internet names
    if this machine can resolve them. Use -LocalOnly to restrict the check to
    names within your own (e.g. Active Directory) domains, and -Strict to
    require the name to exist in a zone hosted on your own DNS server.

.PARAMETER csrBase64
    The PKCS#10 CSR encoded as a base64 string. PEM header/footer are optional.

.PARAMETER LocalOnly
    Only accept SANs that are within one of the allowed domains (see
    -AllowedDomains) and resolve in DNS. SANs outside those domains fail
    without being looked up. Single-label names (e.g. "web01") fail, as they
    are not fully qualified. Wildcard SANs (e.g. "*.corp.example.com") pass if
    they are within an allowed domain; they are not resolved.

.PARAMETER AllowedDomains
    The DNS suffixes that count as local when -LocalOnly or -Strict is used,
    e.g. "corp.example.com","example.local". A SAN matches if it equals one of
    these or ends with "." followed by one of these. If omitted, the Active
    Directory domain of this computer is used; if the computer is not domain
    joined, this parameter is required.

.PARAMETER DnsServer
    One or more DNS servers to query, e.g. your domain controllers. If omitted,
    the DNS servers configured on this machine are used. With -Strict, the
    first server is the one whose zones are checked.

.PARAMETER Strict
    Implies -LocalOnly. Instead of resolving each SAN, checks that an A, AAAA
    or CNAME record for it exists in a forward lookup zone hosted on the DNS
    server (the first -DnsServer, or a domain controller of this computer's
    domain). This is not fooled by split-brain DNS or cached external answers.
    Requires the DnsServer PowerShell module (RSAT DNS Server Tools) and an
    account permitted to read the zones (typically DnsAdmins or higher).
    Names in zones delegated to other servers will not be found.

.EXAMPLE
    .\Test-CsrSANsInDNS.ps1 -csrBase64 "MIICpDCCAYwCAQAwIz..."

.EXAMPLE
    .\Test-CsrSANsInDNS.ps1 -csrBase64 (Get-Content .\request.csr -Raw)

.EXAMPLE
    .\Test-CsrSANsInDNS.ps1 -csrBase64 (Get-Content .\request.csr -Raw) -LocalOnly

    Only accepts SANs within this computer's AD domain.

.EXAMPLE
    .\Test-CsrSANsInDNS.ps1 -csrBase64 $csr -LocalOnly -AllowedDomains corp.example.com,example.local -DnsServer dc01.corp.example.com

.EXAMPLE
    .\Test-CsrSANsInDNS.ps1 -csrBase64 $csr -Strict -DnsServer dc01.corp.example.com
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'Base64-encoded PKCS#10 CSR')]
    [string]$csrBase64,

    [switch]$LocalOnly,

    [string[]]$AllowedDomains,

    [string[]]$DnsServer,

    [switch]$Strict
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
function Write-Log {
    param (
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')]
        [string]$Level,
        [string]$Message
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $line = "$timestamp $Level $Message"
    Write-Host $line
}

Write-Log 'INFO' ('=' * 70)
Write-Log 'INFO' 'CSR SAN DNS validation started'

# ---------------------------------------------------------------------------
# Step 1 - Decode base64 CSR to raw DER bytes
# ---------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($csrBase64)) {
    Write-Error "The -csrBase64 parameter did not contain any CSR data."
    exit 1
}

$cleanBase64 = $csrBase64 `
    -replace '-----BEGIN (NEW )?CERTIFICATE REQUEST-----', '' `
    -replace '-----END (NEW )?CERTIFICATE REQUEST-----',   '' `
    -replace '\s', ''

try {
    $derBytes = [Convert]::FromBase64String($cleanBase64)
    Write-Log 'INFO' "CSR decoded successfully ($($derBytes.Length) bytes)"
}
catch {
    Write-Log 'ERROR' "Failed to decode base64 CSR: $_"
    exit 1
}

# ---------------------------------------------------------------------------
# Step 2 - DER/ASN.1 parser helpers
# ---------------------------------------------------------------------------

# Reads a BER/DER length field at $pos in $Data, returns the length value,
# and advances $pos past the length bytes.
# NOTE: parameter must be [ref] without a type constraint to avoid PowerShell's
# reference-transformation bug when passing ([ref]$intVar).
function Read-DerLength {
    param (
        [byte[]]$Data,
        [ref]$Pos        # holds an [int]; no type annotation on purpose
    )
    $b = [int]$Data[$Pos.Value]
    $Pos.Value++

    if ($b -lt 0x80) {
        return $b
    }

    $numBytes = $b -band 0x7F
    [int]$len = 0
    for ($i = 0; $i -lt $numBytes; $i++) {
        $len = ($len -shl 8) -bor [int]$Data[$Pos.Value]
        $Pos.Value++
    }
    return $len
}

# ---------------------------------------------------------------------------
# Step 3 - Extract DNS SANs from raw DER bytes
# ---------------------------------------------------------------------------
function Get-DnsSansFromDer {
    param ([byte[]]$Der)

    # Always return a typed string array so .Count is always safe
    [string[]]$result = @()

    # SAN extension OID 2.5.29.17 encodes as value bytes: 55 1D 11
    # In a DER TLV it appears as: 06 03 55 1D 11
    $sanOidValue = [byte[]]@(0x55, 0x1D, 0x11)

    for ($i = 2; $i -le ($Der.Length - $sanOidValue.Length); $i++) {
        # Match OID value bytes
        if ($Der[$i]   -ne $sanOidValue[0]) { continue }
        if ($Der[$i+1] -ne $sanOidValue[1]) { continue }
        if ($Der[$i+2] -ne $sanOidValue[2]) { continue }

        # Verify preceding TLV: tag 0x06 (OID), length 0x03
        if ($Der[$i-2] -ne 0x06 -or $Der[$i-1] -ne 0x03) { continue }

        # Cursor lands immediately after the OID bytes
        $pos = $i + 3

        # Structure after OID:
        #   BOOLEAN  (optional, critical flag)  tag 0x01
        #   OCTET STRING                        tag 0x04
        #     SEQUENCE (GeneralNames)           tag 0x30
        #       dNSName entries                 tag 0x82

        # Skip optional critical BOOLEAN
        if ($pos -lt $Der.Length -and $Der[$pos] -eq 0x01) {
            $pos++                              # skip tag
            $bLen = [int]$Der[$pos]; $pos++     # skip length byte
            $pos += $bLen                       # skip value
        }

        # Expect OCTET STRING (0x04)
        if ($pos -ge $Der.Length -or $Der[$pos] -ne 0x04) {
            Write-Log 'WARN' ("Expected OCTET STRING (0x04) after SAN OID, got 0x{0:X2} - skipping" -f $Der[$pos])
            continue
        }
        $pos++
        $pos_ref = [ref]$pos
        $null = Read-DerLength -Data $Der -Pos $pos_ref
        $pos = $pos_ref.Value

        # Expect SEQUENCE (0x30)
        if ($pos -ge $Der.Length -or $Der[$pos] -ne 0x30) {
            Write-Log 'WARN' ("Expected SEQUENCE (0x30) inside SAN OCTET STRING, got 0x{0:X2} - skipping" -f $Der[$pos])
            continue
        }
        $pos++
        $pos_ref = [ref]$pos
        $seqLen  = Read-DerLength -Data $Der -Pos $pos_ref
        $pos     = $pos_ref.Value
        $seqEnd  = $pos + $seqLen

        # Walk each GeneralName entry
        while ($pos -lt $seqEnd) {
            $tag = [int]$Der[$pos]; $pos++
            $pos_ref = [ref]$pos
            $nameLen = Read-DerLength -Data $Der -Pos $pos_ref
            $pos     = $pos_ref.Value

            if ($tag -eq 0x82 -and $nameLen -gt 0) {
                # 0x82 = dNSName [2] IMPLICIT IA5String
                $result += [System.Text.Encoding]::ASCII.GetString($Der, $pos, $nameLen)
            }
            $pos += $nameLen
        }

        break   # RFC 5280: only one SAN extension per certificate/CSR
    }

    return $result
}

# ---------------------------------------------------------------------------
# Step 4 - Extract SANs
# ---------------------------------------------------------------------------
try {
    [string[]]$dnsSans = Get-DnsSansFromDer -Der $derBytes
}
catch {
    Write-Log 'ERROR' "SAN extraction failed: $_"
    exit 1
}

if (@($dnsSans).Count -eq 0) {
    Write-Log 'WARN' 'No DNS SANs found in the CSR'
    Write-Log 'INFO' 'Nothing to validate - exiting with code 0'
    Write-Log 'INFO' ('=' * 70)
    exit 0
}

Write-Log 'INFO' "$($dnsSans.Count) DNS SAN(s) found in CSR:"
foreach ($san in $dnsSans) {
    Write-Log 'INFO' "  -> $san"
}

# ---------------------------------------------------------------------------
# Step 5 - Determine what counts as local (-LocalOnly / -Strict only)
# ---------------------------------------------------------------------------
if ($Strict) { $LocalOnly = $true }

# Lower-cases a DNS name and removes any trailing dot, for comparison
function ConvertTo-NormalisedName {
    param ([string]$Name)
    return $Name.Trim().TrimEnd('.').ToLowerInvariant()
}

# Returns $true if $Name is $Domain or a name within it
function Test-NameInDomain {
    param (
        [string]$Name,
        [string]$Domain
    )
    return ($Name -eq $Domain) -or $Name.EndsWith(".$Domain")
}

[string[]]$localDomains = @()
if ($LocalOnly) {
    if ($AllowedDomains) {
        # Also accept a single comma-separated string, e.g. "a.com,b.com"
        $localDomains = @($AllowedDomains |
            ForEach-Object { $_ -split ',' } |
            ForEach-Object { (ConvertTo-NormalisedName $_).TrimStart('.') } |
            Where-Object { $_ })
    }
    else {
        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
            if ($computerSystem.PartOfDomain) {
                $localDomains = @(ConvertTo-NormalisedName $computerSystem.Domain)
            }
        }
        catch {
            Write-Log 'WARN' "Could not determine this computer's domain: $($_.Exception.Message)"
        }
    }

    if ($localDomains.Count -eq 0) {
        Write-Log 'ERROR' 'No local domains to check against. This computer is not domain joined (or its domain could not be read) - specify them with -AllowedDomains'
        exit 1
    }
    Write-Log 'INFO' "Local-only mode: allowed domain(s): $($localDomains -join ', ')"
}

$zoneServer = $null
[string[]]$localZones = @()
if ($Strict) {
    if (-not (Get-Module -ListAvailable -Name DnsServer)) {
        Write-Log 'ERROR' '-Strict requires the DnsServer PowerShell module (install the RSAT DNS Server Tools)'
        exit 1
    }
    Import-Module DnsServer

    if ($DnsServer) {
        $zoneServer = $DnsServer[0]
    }
    else {
        try {
            $zoneServer = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().FindDomainController().Name
        }
        catch {
            Write-Log 'ERROR' "Could not locate a domain controller - specify the DNS server with -DnsServer ($($_.Exception.Message))"
            exit 1
        }
    }

    try {
        $localZones = @(Get-DnsServerZone -ComputerName $zoneServer -ErrorAction Stop |
            Where-Object {
                -not $_.IsReverseLookupZone -and
                -not $_.IsAutoCreated -and
                $_.ZoneType -in @('Primary', 'Secondary')
            } |
            ForEach-Object { ConvertTo-NormalisedName $_.ZoneName })
    }
    catch {
        Write-Log 'ERROR' "Failed to read the DNS zones on $zoneServer ($($_.Exception.Message))"
        exit 1
    }

    if ($localZones.Count -eq 0) {
        Write-Log 'ERROR' "No forward lookup zones found on $zoneServer"
        exit 1
    }
    Write-Log 'INFO' "Strict mode: checking zone(s) hosted on $zoneServer : $($localZones -join ', ')"
}

# ---------------------------------------------------------------------------
# Step 6 - DNS check
# ---------------------------------------------------------------------------

# Resolves $Name via DNS only (no hosts file, LLMNR or NetBIOS) and returns
# the answers as a string. Throws if DNS returns no answer records.
function Resolve-SanInDns {
    param ([string]$Name)

    $resolveParams = @{
        Name        = $Name
        DnsOnly     = $true
        NoHostsFile = $true
        ErrorAction = 'Stop'
    }
    if ($DnsServer) { $resolveParams.Server = $DnsServer }

    # A name that exists with no A/AAAA records returns only an SOA record in
    # the Authority section rather than an error
    $answers = @(Resolve-DnsName @resolveParams | Where-Object { $_.Section -eq 'Answer' })
    if ($answers.Count -eq 0) {
        throw 'DNS returned no answer records'
    }

    # Records differ in type (e.g. CNAME has no IPAddress) so check each
    # property exists before reading it, as required by StrictMode
    return ($answers |
        ForEach-Object {
            if ($_.PSObject.Properties['IPAddress'])    { $_.IPAddress }
            elseif ($_.PSObject.Properties['NameHost']) { $_.NameHost }
        } |
        Where-Object { $_ }
    ) -join ', '
}

# Looks up $Name in the zones hosted on $zoneServer and returns the matching
# records as a string. Throws if there is no A, AAAA or CNAME record for it.
# A wildcard name only needs to be within a hosted zone.
function Get-SanFromLocalZone {
    param ([string]$Name)

    $isWildcard = $Name.StartsWith('*.')
    $baseName   = if ($isWildcard) { $Name.Substring(2) } else { $Name }

    # The most specific zone containing the name
    $zone = $localZones |
        Where-Object { Test-NameInDomain -Name $baseName -Domain $_ } |
        Sort-Object -Property Length -Descending |
        Select-Object -First 1
    if (-not $zone) {
        throw "not within any forward lookup zone hosted on $zoneServer"
    }
    if ($isWildcard) {
        return "wildcard within zone $zone"
    }

    $relativeName = if ($Name -eq $zone) { '@' } else { $Name.Substring(0, $Name.Length - $zone.Length - 1) }
    try {
        $records = @(Get-DnsServerResourceRecord -ComputerName $zoneServer -ZoneName $zone -Name $relativeName -ErrorAction Stop |
            Where-Object { $_.RecordType -in @('A', 'AAAA', 'CNAME') })
    }
    catch {
        throw "no record for '$relativeName' in zone $zone on $zoneServer ($($_.Exception.Message))"
    }
    if ($records.Count -eq 0) {
        throw "no A, AAAA or CNAME record for '$relativeName' in zone $zone on $zoneServer"
    }

    $targets = ($records |
        ForEach-Object {
            # $_ is rebound inside switch, so keep a reference to the record
            $record = $_
            switch ($record.RecordType) {
                'A'     { $record.RecordData.IPv4Address.IPAddressToString }
                'AAAA'  { $record.RecordData.IPv6Address.IPAddressToString }
                'CNAME' { $record.RecordData.HostNameAlias }
            }
        }
    ) -join ', '
    return "$targets (zone $zone)"
}

$allResolved = $true

foreach ($rawSan in $dnsSans) {
    $san = ConvertTo-NormalisedName $rawSan
    Write-Log 'INFO' "Checking DNS for: $san"

    $isWildcard = $san.StartsWith('*.')

    if ($LocalOnly) {
        $baseName = if ($isWildcard) { $san.Substring(2) } else { $san }

        if (-not $baseName.Contains('.')) {
            Write-Log 'WARN' "  REJECTED  $san (not a fully qualified name)"
            $allResolved = $false
            continue
        }

        $inLocalDomain = @($localDomains | Where-Object { Test-NameInDomain -Name $baseName -Domain $_ }).Count -gt 0
        if (-not $inLocalDomain) {
            Write-Log 'WARN' "  REJECTED  $san (not within an allowed domain: $($localDomains -join ', '))"
            $allResolved = $false
            continue
        }

        if ($isWildcard -and -not $Strict) {
            Write-Log 'SUCCESS' "  ALLOWED   $san (wildcard within an allowed domain - not resolved)"
            continue
        }
    }

    try {
        if ($Strict) {
            $targets = Get-SanFromLocalZone -Name $san
        }
        else {
            $targets = Resolve-SanInDns -Name $san
        }
        Write-Log 'SUCCESS' "  RESOLVED  $san -> $targets"
    }
    catch {
        Write-Log 'WARN' "  NOT FOUND $san ($($_.Exception.Message))"
        $allResolved = $false
    }
}

# ---------------------------------------------------------------------------
# Step 7 - Return result
# ---------------------------------------------------------------------------
if ($allResolved) {
    Write-Log 'SUCCESS' 'All DNS SANs resolved successfully'
    Write-Log 'INFO' 'Exiting with code 0 (all SANs registered)'
    Write-Log 'INFO' ('=' * 70)
    exit 0
}
else {
    Write-Log 'ERROR' 'One or more DNS SANs could not be resolved'
    Write-Log 'INFO' 'Exiting with code 1 (missing DNS registration)'
    Write-Log 'INFO' ('=' * 70)
    exit 1
}
