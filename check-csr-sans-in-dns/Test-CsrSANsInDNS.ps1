<#
.SYNOPSIS
    Validates that all DNS SANs in a PKCS#10 CSR are registered in DNS.

.DESCRIPTION
    Accepts a base64-encoded CSR (with or without PEM headers), extracts all
    DNS Subject Alternative Names, and resolves each via DNS. Returns 0 if all
    SANs resolve successfully, or 1 if any SAN cannot be found. Results are
    written to check-san-log.txt in the same directory as this script.

.PARAMETER csrBase64
    The PKCS#10 CSR encoded as a base64 string. PEM header/footer are optional.

.EXAMPLE
    .\Check-SanDns.ps1 -csrBase64 "MIICpDCCAYwCAQAwIz..."

.EXAMPLE
    .\Check-SanDns.ps1 -csrBase64 (Get-Content .\request.csr -Raw)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'Base64-encoded PKCS#10 CSR')]
    [string]$csrBase64
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
# Step 5 - DNS resolution check
# ---------------------------------------------------------------------------
$allResolved = $true

foreach ($san in $dnsSans) {
    Write-Log 'INFO' "Checking DNS for: $san"
    try {
        $records = Resolve-DnsName -Name $san -ErrorAction Stop
        $targets = ($records |
            ForEach-Object {
                if ($_.IPAddress)    { $_.IPAddress }
                elseif ($_.NameHost) { $_.NameHost }
            } |
            Where-Object { $_ }
        ) -join ', '
        Write-Log 'SUCCESS' "  RESOLVED  $san -> $targets"
    }
    catch {
        Write-Log 'WARN' "  NOT FOUND $san ($($_.Exception.Message))"
        $allResolved = $false
    }
}

# ---------------------------------------------------------------------------
# Step 6 - Return result
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