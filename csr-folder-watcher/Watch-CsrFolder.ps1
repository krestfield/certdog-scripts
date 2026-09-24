<#
.SYNOPSIS
    Watches a directory for PKCS#10 CSR files, submits valid ones to the Certdog REST API,
    and files the results (issued certs, processed CSRs, failed files, logs).

.DESCRIPTION
    For every file found directly inside -watchDirectory:
      1. Reads it as a PEM, bare base64 or binary DER PKCS#10 CSR and checks its structure.
      2. If parsing fails      -> file is moved to <watchDirectory>\failed, logged with the reason.
      3. If parsing succeeds   -> DN, SANs and key algorithm are extracted (for logging), and
                                   the CSR is POSTed to $apiUrl/certs/requestp10.
           - On success        -> issued cert saved to <watchDirectory>\issued\<name>.cer,
                                   original CSR moved to <watchDirectory>\processed, logged.
           - On API failure    -> original CSR moved to <watchDirectory>\failed, logged.

    A log file named <yyyyMMdd>.log is written/appended to <watchDirectory>\logs for each run.

    The CSR is parsed by a small built-in DER reader rather than certutil or the Windows
    crypto APIs. This means the script:
      - does not depend on PATH, the system display language, or the account it runs as;
      - accepts any key/signature algorithm (RSA, ECDSA, EdDSA, ML-DSA, SLH-DSA, ...),
        because it checks the PKCS#10 structure without needing to understand the key.

.PARAMETER apiUrl
    Base URL of the Certdog REST API, e.g. https://certdog.example.com/api

.PARAMETER apiToken
    Bearer token used to authenticate to the Certdog REST API.

.PARAMETER watchDirectory
    Directory to scan for CSR files.

.PARAMETER issuerId
    Certdog issuer ID to request the certificate from.

.PARAMETER teamId
    Certdog team ID to associate the certificate with.

.EXAMPLE
    .\Watch-CsrFolder.ps1 -apiUrl "https://certdog.example.com/api" -apiToken "abcdef123456" `
        -watchDirectory "C:\certs" -issuerId "63f1..." -teamId "63f2..."

.NOTES
    The CSR's signature is NOT verified locally (doing so would tie the script to whichever
    algorithms the local OS supports). Certdog verifies the signature when the request is
    submitted, and a CSR with a bad signature ends up in \failed with Certdog's error logged.

    NOTE / ASSUMPTION: the spec does not say where a CSR should go if it parses OK but Certdog
    fails to issue a certificate for it. This script moves it to the \failed folder (rather
    than leaving it in watchDirectory) so it is not repeatedly reprocessed on the next run.
    Adjust the "API failure" branch below if different behaviour is required.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$apiUrl,
    [Parameter(Mandatory = $true)][string]$apiToken,
    [Parameter(Mandatory = $true)][string]$watchDirectory,
    [Parameter(Mandatory = $true)][string]$issuerId,
    [Parameter(Mandatory = $true)][string]$teamId
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $watchDirectory -PathType Container)) {
    throw "watchDirectory '$watchDirectory' does not exist or is not a directory."
}

$watchDirectory = (Resolve-Path -LiteralPath $watchDirectory).Path.TrimEnd('\', '/')

$issuedDir    = Join-Path $watchDirectory 'issued'
$processedDir = Join-Path $watchDirectory 'processed'
$failedDir    = Join-Path $watchDirectory 'failed'
$logsDir      = Join-Path $watchDirectory 'logs'

foreach ($dir in @($issuedDir, $processedDir, $failedDir, $logsDir)) {
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
}

$logFile = Join-Path $logsDir ((Get-Date -Format 'yyyyMMdd') + '.log')

function Write-Log {
    param([Parameter(Mandatory = $true)][string]$Message)

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$timestamp] $Message"
    Add-Content -LiteralPath $logFile -Value $line
    Write-Verbose $line
}

# ---------------------------------------------------------------------------
# OID lookup tables
# ---------------------------------------------------------------------------

$script:DnAttributeNames = @{
    '2.5.4.3'                    = 'CN'
    '2.5.4.4'                    = 'SN'
    '2.5.4.5'                    = 'SERIALNUMBER'
    '2.5.4.6'                    = 'C'
    '2.5.4.7'                    = 'L'
    '2.5.4.8'                    = 'S'
    '2.5.4.9'                    = 'STREET'
    '2.5.4.10'                   = 'O'
    '2.5.4.11'                   = 'OU'
    '2.5.4.12'                   = 'T'
    '2.5.4.42'                   = 'G'
    '2.5.4.43'                   = 'I'
    '1.2.840.113549.1.9.1'       = 'E'
    '0.9.2342.19200300.100.1.1'  = 'UID'
    '0.9.2342.19200300.100.1.25' = 'DC'
}

$script:AlgorithmNames = @{
    # Public key algorithms
    '1.2.840.113549.1.1.1'    = 'RSA'
    '1.2.840.113549.1.1.10'   = 'RSASSA-PSS'
    '1.2.840.10045.2.1'       = 'ECDSA'
    '1.3.101.112'             = 'Ed25519'
    '1.3.101.113'             = 'Ed448'
    # Post-quantum (FIPS 204 ML-DSA, FIPS 205 SLH-DSA)
    '2.16.840.1.101.3.4.3.17' = 'ML-DSA-44'
    '2.16.840.1.101.3.4.3.18' = 'ML-DSA-65'
    '2.16.840.1.101.3.4.3.19' = 'ML-DSA-87'
    '2.16.840.1.101.3.4.3.20' = 'SLH-DSA-SHA2-128s'
    '2.16.840.1.101.3.4.3.21' = 'SLH-DSA-SHA2-128f'
    '2.16.840.1.101.3.4.3.22' = 'SLH-DSA-SHA2-192s'
    '2.16.840.1.101.3.4.3.23' = 'SLH-DSA-SHA2-192f'
    '2.16.840.1.101.3.4.3.24' = 'SLH-DSA-SHA2-256s'
    '2.16.840.1.101.3.4.3.25' = 'SLH-DSA-SHA2-256f'
    '2.16.840.1.101.3.4.3.26' = 'SLH-DSA-SHAKE-128s'
    '2.16.840.1.101.3.4.3.27' = 'SLH-DSA-SHAKE-128f'
    '2.16.840.1.101.3.4.3.28' = 'SLH-DSA-SHAKE-192s'
    '2.16.840.1.101.3.4.3.29' = 'SLH-DSA-SHAKE-192f'
    '2.16.840.1.101.3.4.3.30' = 'SLH-DSA-SHAKE-256s'
    '2.16.840.1.101.3.4.3.31' = 'SLH-DSA-SHAKE-256f'
    # Elliptic curves (ECDSA key parameters)
    '1.2.840.10045.3.1.7'     = 'P-256'
    '1.3.132.0.34'            = 'P-384'
    '1.3.132.0.35'            = 'P-521'
}

$script:OidExtensionRequest    = '1.2.840.113549.1.9.14'
$script:OidMsExtensionRequest  = '1.3.6.1.4.1.311.2.1.14'
$script:OidSubjectAltName      = '2.5.29.17'
$script:OidUpn                 = '1.3.6.1.4.1.311.20.2.3'

function Get-AlgorithmName {
    param([Parameter(Mandatory = $true)][string]$Oid)

    if ($script:AlgorithmNames.ContainsKey($Oid)) { return $script:AlgorithmNames[$Oid] }
    return "OID $Oid"
}

# ---------------------------------------------------------------------------
# Minimal DER reader
# ---------------------------------------------------------------------------

# Reads the tag/length header of the DER element at $Offset. The element must fit
# entirely before $Limit. Returns the element's tag and the bounds of its content.
function Read-DerElement {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][int]$Limit
    )

    if ($Offset + 2 -gt $Limit) {
        throw "ASN.1 data is truncated at offset $Offset."
    }

    $tag = [int]$Bytes[$Offset]
    if (($tag -band 0x1F) -eq 0x1F) {
        throw "Unsupported multi-byte ASN.1 tag at offset $Offset."
    }

    $lengthByte = [int]$Bytes[$Offset + 1]
    $pos = $Offset + 2

    if ($lengthByte -lt 0x80) {
        $length = [long]$lengthByte
    }
    elseif ($lengthByte -eq 0x80) {
        throw "Indefinite-length ASN.1 encoding at offset $Offset is not valid DER."
    }
    else {
        $lengthBytes = $lengthByte -band 0x7F
        if ($lengthBytes -gt 4) {
            throw "ASN.1 length at offset $Offset is too large."
        }
        if ($pos + $lengthBytes -gt $Limit) {
            throw "ASN.1 data is truncated at offset $Offset."
        }
        $length = [long]0
        for ($i = 0; $i -lt $lengthBytes; $i++) {
            $length = ($length * 256) + $Bytes[$pos + $i]
        }
        $pos += $lengthBytes
    }

    if ($pos + $length -gt $Limit) {
        throw "ASN.1 element at offset $Offset runs past the end of its container."
    }

    return [pscustomobject]@{
        Tag    = $tag
        Offset = $Offset
        Start  = $pos
        Length = [int]$length
        End    = $pos + [int]$length
    }
}

# Returns the child elements of a constructed element. The children must exactly
# fill the parent's content.
function Get-DerChildren {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)]$Parent
    )

    $children = New-Object System.Collections.Generic.List[object]
    $pos = $Parent.Start
    while ($pos -lt $Parent.End) {
        $child = Read-DerElement -Bytes $Bytes -Offset $pos -Limit $Parent.End
        $children.Add($child)
        $pos = $child.End
    }
    return ,$children
}

function Assert-DerTag {
    param(
        [Parameter(Mandatory = $true)]$Element,
        [Parameter(Mandatory = $true)][int]$Tag,
        [Parameter(Mandatory = $true)][string]$What
    )

    if ($Element.Tag -ne $Tag) {
        throw ("{0}: expected ASN.1 tag 0x{1:X2} but found 0x{2:X2} at offset {3}." -f `
                $What, $Tag, $Element.Tag, $Element.Offset)
    }
}

function Get-DerContent {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)]$Element
    )

    $content = New-Object byte[] $Element.Length
    [Array]::Copy($Bytes, $Element.Start, $content, 0, $Element.Length)
    return ,$content
}

# Decodes the content of an OBJECT IDENTIFIER (or an implicitly tagged one, such as a
# registeredID SAN) into dotted form. The caller is responsible for checking the tag.
function ConvertFrom-DerOid {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)]$Element
    )

    if ($Element.Length -lt 1) {
        throw "Empty OBJECT IDENTIFIER at offset $($Element.Offset)."
    }

    $arcs = New-Object System.Collections.Generic.List[string]
    $value = [long]0
    $first = $true
    $tooLarge = $false

    for ($i = $Element.Start; $i -lt $Element.End; $i++) {
        $b = [int]$Bytes[$i]
        if ($value -gt 0x00FFFFFFFFFFFFFF) {
            # Arc will not fit in 64 bits (e.g. UUID-based 2.25.x OIDs). Such OIDs are
            # never ones this script needs to recognise, so just mark it.
            $tooLarge = $true
            $value = 0
        }
        $value = ($value * 128) + ($b -band 0x7F)

        if (($b -band 0x80) -eq 0) {
            if ($first) {
                if ($value -lt 40)     { $arcs.Add('0'); $arcs.Add([string]$value) }
                elseif ($value -lt 80) { $arcs.Add('1'); $arcs.Add([string]($value - 40)) }
                else                   { $arcs.Add('2'); $arcs.Add([string]($value - 80)) }
                $first = $false
            }
            else {
                $arcs.Add([string]$value)
            }
            $value = [long]0
        }
        elseif ($i -eq $Element.End - 1) {
            throw "Malformed OBJECT IDENTIFIER at offset $($Element.Offset)."
        }
    }

    if ($tooLarge) { return '(unrecognised OID)' }
    return ($arcs -join '.')
}

# Decodes an ASN.1 string value (as found in DNs and SANs) into text.
function ConvertFrom-DerString {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)]$Element
    )

    $content = Get-DerContent -Bytes $Bytes -Element $Element
    $tag = $Element.Tag

    if ($tag -eq 0x0C) {
        return [System.Text.Encoding]::UTF8.GetString($content)                  # UTF8String
    }
    elseif ($tag -eq 0x12 -or $tag -eq 0x13 -or $tag -eq 0x16 -or $tag -eq 0x1A) {
        return [System.Text.Encoding]::ASCII.GetString($content)                 # Numeric/Printable/IA5/Visible
    }
    elseif ($tag -eq 0x14) {
        return [System.Text.Encoding]::GetEncoding(28591).GetString($content)    # TeletexString (as Latin-1)
    }
    elseif ($tag -eq 0x1E) {
        return [System.Text.Encoding]::BigEndianUnicode.GetString($content)      # BMPString
    }
    elseif ($tag -eq 0x1C) {
        return (New-Object System.Text.UTF32Encoding($true, $false)).GetString($content)  # UniversalString
    }

    return '#' + [BitConverter]::ToString($content).Replace('-', '')
}

# Quotes a DN attribute value if it contains characters that are special in a DN string.
function Format-DnValue {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    if ($Value -match '[,+"\\<>;=\r\n]' -or $Value -match '^[\s#]' -or $Value -match '\s$') {
        return '"' + $Value.Replace('"', '""') + '"'
    }
    return $Value
}

# Decodes an X.501 Name into a Windows-style DN string, most specific RDN first,
# e.g. "CN=server1.example.com, O=Example, C=GB".
function ConvertFrom-DerName {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)]$Element
    )

    Assert-DerTag -Element $Element -Tag 0x30 -What 'Subject'

    $rdns = New-Object System.Collections.Generic.List[string]
    foreach ($rdn in (Get-DerChildren -Bytes $Bytes -Parent $Element)) {
        Assert-DerTag -Element $rdn -Tag 0x31 -What 'Subject RDN'

        $attributes = New-Object System.Collections.Generic.List[string]
        foreach ($atv in (Get-DerChildren -Bytes $Bytes -Parent $rdn)) {
            Assert-DerTag -Element $atv -Tag 0x30 -What 'Subject attribute'
            $parts = Get-DerChildren -Bytes $Bytes -Parent $atv
            if ($parts.Count -ne 2) {
                throw "Subject attribute at offset $($atv.Offset) is malformed."
            }
            Assert-DerTag -Element $parts[0] -Tag 0x06 -What 'Subject attribute type'

            $oid = ConvertFrom-DerOid -Bytes $Bytes -Element $parts[0]
            $name = if ($script:DnAttributeNames.ContainsKey($oid)) { $script:DnAttributeNames[$oid] } else { "OID.$oid" }
            $value = ConvertFrom-DerString -Bytes $Bytes -Element $parts[1]
            $attributes.Add("$name=$(Format-DnValue -Value $value)")
        }
        $rdns.Add(($attributes -join ' + '))
    }

    if ($rdns.Count -eq 0) { return '(empty DN)' }
    $rdns.Reverse()
    return ($rdns -join ', ')
}

# Decodes the GeneralNames inside a Subject Alternative Name extension value into
# entries such as "DNS:server2.local.com" and "IP:10.2.34.4".
function ConvertFrom-DerGeneralNames {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)]$ExtensionValue
    )

    $names = Read-DerElement -Bytes $Bytes -Offset $ExtensionValue.Start -Limit $ExtensionValue.End
    Assert-DerTag -Element $names -Tag 0x30 -What 'Subject Alternative Name'
    if ($names.End -ne $ExtensionValue.End) {
        throw 'Subject Alternative Name extension has unexpected trailing data.'
    }

    $sans = New-Object System.Collections.Generic.List[string]
    foreach ($gn in (Get-DerChildren -Bytes $Bytes -Parent $names)) {
        switch ($gn.Tag) {
            0x81 { $sans.Add('EMAIL:' + [System.Text.Encoding]::ASCII.GetString((Get-DerContent -Bytes $Bytes -Element $gn))) }
            0x82 { $sans.Add('DNS:'   + [System.Text.Encoding]::ASCII.GetString((Get-DerContent -Bytes $Bytes -Element $gn))) }
            0x86 { $sans.Add('URI:'   + [System.Text.Encoding]::ASCII.GetString((Get-DerContent -Bytes $Bytes -Element $gn))) }
            0x87 {
                $ipBytes = Get-DerContent -Bytes $Bytes -Element $gn
                if ($ipBytes.Length -eq 4 -or $ipBytes.Length -eq 16) {
                    $ip = New-Object System.Net.IPAddress -ArgumentList (,$ipBytes)
                    $sans.Add('IP:' + $ip.ToString())
                }
                else {
                    $sans.Add('IP:#' + [BitConverter]::ToString($ipBytes).Replace('-', ''))
                }
            }
            0x88 { $sans.Add('RID:' + (ConvertFrom-DerOid -Bytes $Bytes -Element $gn)) }
            0xA0 {
                # otherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
                $parts = Get-DerChildren -Bytes $Bytes -Parent $gn
                if ($parts.Count -ne 2 -or $parts[0].Tag -ne 0x06 -or $parts[1].Tag -ne 0xA0) {
                    throw "Subject Alternative Name otherName at offset $($gn.Offset) is malformed."
                }
                $typeOid = ConvertFrom-DerOid -Bytes $Bytes -Element $parts[0]
                $inner = Get-DerChildren -Bytes $Bytes -Parent $parts[1]
                if ($typeOid -eq $script:OidUpn -and $inner.Count -eq 1) {
                    $sans.Add('UPN:' + (ConvertFrom-DerString -Bytes $Bytes -Element $inner[0]))
                }
                else {
                    $sans.Add("otherName:$typeOid")
                }
            }
            0xA4 {
                $inner = Get-DerChildren -Bytes $Bytes -Parent $gn
                if ($inner.Count -ne 1) {
                    throw "Subject Alternative Name directoryName at offset $($gn.Offset) is malformed."
                }
                $sans.Add('DirName:' + (ConvertFrom-DerName -Bytes $Bytes -Element $inner[0]))
            }
            default { $sans.Add(('[tag 0x{0:X2}]' -f $gn.Tag)) }
        }
    }
    return ,$sans
}

# ---------------------------------------------------------------------------
# CSR reading and parsing
# ---------------------------------------------------------------------------

# Reads a CSR file and returns its DER bytes. Accepts PEM (with any
# "-----BEGIN ...REQUEST-----" header), bare base64, or binary DER.
function Get-CsrDer {
    param([Parameter(Mandatory = $true)][string]$FilePath)

    $raw = [System.IO.File]::ReadAllBytes($FilePath)
    if ($raw.Length -eq 0) {
        throw 'The file is empty.'
    }

    # Binary DER always starts with a SEQUENCE tag.
    if ($raw[0] -eq 0x30) {
        return ,$raw
    }

    if ($raw.Length -ge 2 -and $raw[0] -eq 0xFF -and $raw[1] -eq 0xFE) {
        $text = [System.Text.Encoding]::Unicode.GetString($raw, 2, $raw.Length - 2)
    }
    elseif ($raw.Length -ge 2 -and $raw[0] -eq 0xFE -and $raw[1] -eq 0xFF) {
        $text = [System.Text.Encoding]::BigEndianUnicode.GetString($raw, 2, $raw.Length - 2)
    }
    else {
        $text = [System.Text.Encoding]::UTF8.GetString($raw).TrimStart([char]0xFEFF)
    }

    if ($text -match '(?s)-----BEGIN ([^-]*REQUEST)-----(.*?)-----END \1-----') {
        $b64 = $Matches[2]
    }
    elseif ($text -match '-----BEGIN ') {
        throw 'The file is PEM but does not contain a certificate request.'
    }
    elseif ($text.Trim() -match '^[A-Za-z0-9+/=\s]+$') {
        $b64 = $text
    }
    else {
        throw 'The file is not in PEM, base64 or DER format.'
    }

    try {
        $der = [System.Convert]::FromBase64String(($b64 -replace '\s', ''))
    }
    catch {
        throw 'The base64 content could not be decoded.'
    }
    if ($der.Length -eq 0) {
        throw 'The PEM block is empty.'
    }
    return ,$der
}

# Checks that the DER bytes are a structurally valid PKCS#10 CertificationRequest
# (RFC 2986) and extracts the details needed for logging. Throws with a description
# of the problem if the structure is invalid. The signature is not verified.
function ConvertFrom-Pkcs10 {
    param([Parameter(Mandatory = $true)][byte[]]$Der)

    # CertificationRequest ::= SEQUENCE { certificationRequestInfo, signatureAlgorithm, signature }
    $request = Read-DerElement -Bytes $Der -Offset 0 -Limit $Der.Length
    Assert-DerTag -Element $request -Tag 0x30 -What 'CertificationRequest'
    if ($request.End -ne $Der.Length) {
        throw 'Unexpected data after the end of the certificate request.'
    }

    $top = Get-DerChildren -Bytes $Der -Parent $request
    if ($top.Count -ne 3) {
        throw "CertificationRequest should contain 3 elements but contains $($top.Count)."
    }
    $info = $top[0]; $signatureAlgorithm = $top[1]; $signature = $top[2]
    Assert-DerTag -Element $info -Tag 0x30 -What 'CertificationRequestInfo'
    Assert-DerTag -Element $signatureAlgorithm -Tag 0x30 -What 'Signature algorithm'
    Assert-DerTag -Element $signature -Tag 0x03 -What 'Signature'
    if ($signature.Length -lt 2) {
        throw 'The signature is empty.'
    }

    # CertificationRequestInfo ::= SEQUENCE { version, subject, subjectPKInfo, attributes [0] }
    # (attributes is mandatory in RFC 2986 but some tools omit it when empty)
    $infoParts = Get-DerChildren -Bytes $Der -Parent $info
    if ($infoParts.Count -lt 3 -or $infoParts.Count -gt 4) {
        throw "CertificationRequestInfo should contain 3 or 4 elements but contains $($infoParts.Count)."
    }

    $version = $infoParts[0]
    Assert-DerTag -Element $version -Tag 0x02 -What 'Version'
    if ($version.Length -ne 1 -or $Der[$version.Start] -ne 0) {
        throw 'Unsupported certificate request version (expected v1).'
    }

    $subject = ConvertFrom-DerName -Bytes $Der -Element $infoParts[1]

    # SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
    $spki = $infoParts[2]
    Assert-DerTag -Element $spki -Tag 0x30 -What 'Public key info'
    $spkiParts = Get-DerChildren -Bytes $Der -Parent $spki
    if ($spkiParts.Count -ne 2) {
        throw 'Public key info is malformed.'
    }
    Assert-DerTag -Element $spkiParts[0] -Tag 0x30 -What 'Public key algorithm'
    Assert-DerTag -Element $spkiParts[1] -Tag 0x03 -What 'Public key'
    if ($spkiParts[1].Length -lt 2) {
        throw 'The public key is empty.'
    }

    $keyAlgParts = Get-DerChildren -Bytes $Der -Parent $spkiParts[0]
    if ($keyAlgParts.Count -lt 1) {
        throw 'Public key algorithm is empty.'
    }
    Assert-DerTag -Element $keyAlgParts[0] -Tag 0x06 -What 'Public key algorithm OID'
    $keyAlgorithm = Get-AlgorithmName -Oid (ConvertFrom-DerOid -Bytes $Der -Element $keyAlgParts[0])
    if ($keyAlgParts.Count -gt 1 -and $keyAlgParts[1].Tag -eq 0x06) {
        # ECDSA keys carry the named curve as the algorithm parameter.
        $curve = Get-AlgorithmName -Oid (ConvertFrom-DerOid -Bytes $Der -Element $keyAlgParts[1])
        $keyAlgorithm = "$keyAlgorithm $curve"
    }

    $sigAlgParts = Get-DerChildren -Bytes $Der -Parent $signatureAlgorithm
    if ($sigAlgParts.Count -lt 1) {
        throw 'Signature algorithm is empty.'
    }
    Assert-DerTag -Element $sigAlgParts[0] -Tag 0x06 -What 'Signature algorithm OID'

    # Attributes: look for an extension request carrying a Subject Alternative Name.
    $sans = New-Object System.Collections.Generic.List[string]
    if ($infoParts.Count -eq 4) {
        Assert-DerTag -Element $infoParts[3] -Tag 0xA0 -What 'Attributes'

        foreach ($attribute in (Get-DerChildren -Bytes $Der -Parent $infoParts[3])) {
            Assert-DerTag -Element $attribute -Tag 0x30 -What 'Attribute'
            $attrParts = Get-DerChildren -Bytes $Der -Parent $attribute
            if ($attrParts.Count -ne 2) {
                throw "Attribute at offset $($attribute.Offset) is malformed."
            }
            Assert-DerTag -Element $attrParts[0] -Tag 0x06 -What 'Attribute type'
            Assert-DerTag -Element $attrParts[1] -Tag 0x31 -What 'Attribute values'

            $attrOid = ConvertFrom-DerOid -Bytes $Der -Element $attrParts[0]
            if ($attrOid -ne $script:OidExtensionRequest -and $attrOid -ne $script:OidMsExtensionRequest) {
                continue
            }

            foreach ($extensions in (Get-DerChildren -Bytes $Der -Parent $attrParts[1])) {
                Assert-DerTag -Element $extensions -Tag 0x30 -What 'Requested extensions'

                # Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
                foreach ($extension in (Get-DerChildren -Bytes $Der -Parent $extensions)) {
                    Assert-DerTag -Element $extension -Tag 0x30 -What 'Extension'
                    $extParts = Get-DerChildren -Bytes $Der -Parent $extension
                    if ($extParts.Count -lt 2 -or $extParts.Count -gt 3) {
                        throw "Extension at offset $($extension.Offset) is malformed."
                    }
                    Assert-DerTag -Element $extParts[0] -Tag 0x06 -What 'Extension OID'
                    $extValue = $extParts[$extParts.Count - 1]
                    Assert-DerTag -Element $extValue -Tag 0x04 -What 'Extension value'

                    if ((ConvertFrom-DerOid -Bytes $Der -Element $extParts[0]) -eq $script:OidSubjectAltName) {
                        foreach ($san in (ConvertFrom-DerGeneralNames -Bytes $Der -ExtensionValue $extValue)) {
                            $sans.Add($san)
                        }
                    }
                }
            }
        }
    }

    return [pscustomobject]@{
        Subject            = $subject
        Sans               = $(if ($sans.Count -gt 0) { $sans -join ', ' } else { '(none)' })
        KeyAlgorithm       = $keyAlgorithm
        SignatureAlgorithm = Get-AlgorithmName -Oid (ConvertFrom-DerOid -Bytes $Der -Element $sigAlgParts[0])
    }
}

# ---------------------------------------------------------------------------
# Certdog API call
# ---------------------------------------------------------------------------

function Request-CertdogCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$CsrBase64,
        [Parameter(Mandatory = $true)][string]$ExtraInfo
    )

    $uri = "$($apiUrl.TrimEnd('/'))/certs/requestp10"

    $bodyObj = @{
        issuerId  = $issuerId
        teamId    = $teamId
        csr       = $CsrBase64
        extraInfo = $ExtraInfo
    }
    $body = $bodyObj | ConvertTo-Json -Compress

    $headers = @{
        Authorization = "Bearer $apiToken"
    }

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers `
                        -ContentType 'application/json' -Body $body -ErrorAction Stop
        return [pscustomobject]@{ Success = $true; Response = $response; Error = $null }
    }
    catch {
        $errDetail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $errDetail = $_.ErrorDetails.Message
        }
        return [pscustomobject]@{ Success = $false; Response = $null; Error = $errDetail }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$files = Get-ChildItem -LiteralPath $watchDirectory -File -ErrorAction SilentlyContinue

if (-not $files -or $files.Count -eq 0) {
    Write-Verbose "No files found in $watchDirectory."
    return
}

foreach ($file in $files) {
    $fullPath = $file.FullName

    try {
        $der = Get-CsrDer -FilePath $fullPath
        $csr = ConvertFrom-Pkcs10 -Der $der
    }
    catch {
        $reason = $_.Exception.Message
        $destination = Join-Path $failedDir $file.Name
        Move-Item -LiteralPath $fullPath -Destination $destination -Force
        Write-Log "File: $fullPath was not processed as the file was not a valid CSR ($reason). File moved to the failed folder."
        continue
    }

    # Send the DER that was validated, re-encoded as a single base64 string.
    $csrBase64 = [System.Convert]::ToBase64String($der)

    $result = Request-CertdogCertificate -CsrBase64 $csrBase64 -ExtraInfo $fullPath

    if ($result.Success -and $result.Response.pemCert) {
        $certFileName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name) + '.cer'
        $certPath = Join-Path $issuedDir $certFileName

        try {
            $pemBytes = [System.Convert]::FromBase64String($result.Response.pemCert)
            $pemText  = [System.Text.Encoding]::UTF8.GetString($pemBytes)
            Set-Content -LiteralPath $certPath -Value $pemText -NoNewline
        }
        catch {
            # If pemCert wasn't base64 (already PEM text), fall back to writing it as-is.
            Set-Content -LiteralPath $certPath -Value $result.Response.pemCert -NoNewline
        }

        $processedPath = Join-Path $processedDir $file.Name
        Move-Item -LiteralPath $fullPath -Destination $processedPath -Force

        Write-Log "File: $fullPath was processed OK. Request was for DN: $($csr.Subject) and included SANs $($csr.Sans) (key algorithm: $($csr.KeyAlgorithm)). The certificate has been saved to $certPath"
    }
    else {
        $errMsg = if ($result.Error) { $result.Error } else { 'No error detail returned by Certdog.' }
        $errMsg = ($errMsg -replace '\s*\r?\n\s*', ' ').Trim()   # keep each log entry on one line

        # ASSUMPTION: move CSRs that failed to issue into \failed so they are not
        # reprocessed on the next run. Remove this Move-Item call if you'd rather
        # leave them in watchDirectory for a retry.
        $destination = Join-Path $failedDir $file.Name
        Move-Item -LiteralPath $fullPath -Destination $destination -Force

        Write-Log "File: $fullPath was a valid CSR but a certificate could not be issued. DN: $($csr.Subject), key algorithm: $($csr.KeyAlgorithm). $errMsg"
    }
}
