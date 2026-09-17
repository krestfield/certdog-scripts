<#
.SYNOPSIS
    Extracts certificate details from an Active Directory Certificate Services (AD CS) CA database.

.DESCRIPTION
    Connects to the specified CA via the CertificateAuthority.View COM interface and retrieves
    every certificate that was issued (NotBefore) within the last N days. For each certificate it
    emits an object containing:
      - The certificate itself, Base64-encoded PEM
      - Whether it is revoked, the revocation date/time, and the revocation reason
      - The original CSR, Base64-encoded PEM
      - The certificate template it was issued against
      - The requesting user (RequesterName, typically DOMAIN\user)

.PARAMETER caConfig
    CA configuration string in the form "ServerName\CAName" (as accepted by certutil -config).

.PARAMETER lastDays
    Number of days to look back from today. Certificates with a NotBefore date on or after
    (Today - lastDays) are returned.

.EXAMPLE
    .\Get-AdcsCertificates.ps1 -caConfig "CA01\Contoso-Issuing-CA" -lastDays 7

.EXAMPLE
    .\Get-AdcsCertificates.ps1 -caConfig "CA01\Contoso-Issuing-CA" -lastDays 30 |
        Select-Object RequestID, Template, RequesterName, Revoked, RevokedWhen, RevokedReason |
        Export-Csv -Path .\certs.csv -NoTypeInformation

.NOTES
    - Must be run as, or with permissions equivalent to, an account that has "Read" access on
      the CA (Certification Authority MMC -> Security tab), or run locally on the CA server
      by an administrator.
    - Requires the AD CS management tools (RSAT-ADCS or the CA role itself) to be installed on
      the machine running the script, since these register the CertificateAuthority.View COM
      component.
    - CSR data (RawRequest) may be empty/null for some requests if it was purged or was never
      archived by the CA, in which case CsrPem will be $null.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[^\\]+\\.+$')]
    [string]$caConfig,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 36500)]
    [int]$lastDays,

    [Parameter(Mandatory = $true)]
    [string]$certdogApiUrl,

    [Parameter(Mandatory = $true)]
    [string]$certdogApiToken,

    [string]$certdogOwnerUserId = "",
    [string]$certdogOwnerTeamId = "",
    [string]$certdogExtraInfo = "",
    [string]$certdogCertIssuerId = ""
)

import-module .\certdog-module.psm1



# ---------------------------------------------------------------------------
# ICertView2 constants (from certcli.h / certview.h)
# ---------------------------------------------------------------------------
$CVR_SEEK_GE          = 0x10   # >=
$CVR_SORT_NONE        = 0
$CV_OUT_BASE64HEADER  = 0      # Return column value as base64 text WITH PEM header/footer
$CV_OUT_BASE64        = 1      # Return column value as base64 text (no PEM header/footer)
$CVRC_COLUMN_SCHEMA   = 0      # GetColumnIndex / EnumCertViewColumn: look up amongst schema columns
$CVRC_COLUMN_RESULT   = 1      # EnumCertViewColumn: look up amongst result columns already set

# Request disposition codes
$DispositionMap = @{
    8  = 'Denied'
    9  = 'Denied'
    12 = 'Pending'
    13 = 'Foreign / External'
    15 = 'Error'
    16 = 'Error'
    17 = 'Error'
    20 = 'Issued'
    21 = 'Revoked'
    30 = 'Error'
    31 = 'Error'
    32 = 'Error'
}

# CRL revocation reason codes
$RevocationReasonMap = @{
    0 = 'Unspecified'
    1 = 'Key Compromise'
    2 = 'CA Compromise'
    3 = 'Affiliation Changed'
    4 = 'Superseded'
    5 = 'Cessation of Operation'
    6 = 'Certificate Hold'
    8 = 'Remove From CRL'
}

function ConvertTo-Pem {
    param(
        [string]$Base64,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($Base64)) {
        return $null
    }

    $wrapped = [regex]::Replace($Base64, '.{1,64}', "`$0`n").TrimEnd()
    return "-----BEGIN $Label-----`n$wrapped`n-----END $Label-----"
}

function Get-Base64ColumnValue {
    param(
        $ColumnObj,
        [string]$ColumnName
    )

    # Try the plain base64 form first, then fall back to the header/footer form and
    # strip the header/footer lines back off. Some CA installs only populate one or
    # the other cleanly for a given column, so trying both makes extraction resilient.
    foreach ($type in @($CV_OUT_BASE64, $CV_OUT_BASE64HEADER)) {
        try {
            $value = $ColumnObj.GetValue($type)
        }
        catch {
            Write-Verbose "GetValue($type) threw for column '$ColumnName': $_"
            $value = $null
        }

        if (-not [string]::IsNullOrWhiteSpace($value)) {
            if ($type -eq $CV_OUT_BASE64HEADER) {
                $value = (($value -split "`r?`n") | Where-Object { $_ -notmatch '^-----' }) -join ''
            }
            return $value
        }
    }

    Write-Verbose "Column '$ColumnName' returned no data for this row."
    return $null
}

function Get-AdcsSchemaColumnNames {
    # Enumerates every column name the CA's schema actually exposes. Different CA
    # versions/builds can expose the same logical field under slightly different
    # names (e.g. "Disposition" vs "Request.Disposition"), and GetColumnIndex can
    # silently resolve a bare name to the wrong/empty column rather than throwing.
    # Discovering real names up front avoids guessing.
    param($CaView)

    $names = New-Object 'System.Collections.Generic.List[string]'
    try {
        $schemaEnum = $CaView.EnumCertViewColumn($CVRC_COLUMN_SCHEMA)
        while ($schemaEnum.Next() -ne -1) {
            [void]$names.Add($schemaEnum.GetName())
        }
    }
    catch {
        Write-Warning "Could not enumerate CA schema columns: $_"
    }

    return $names
}

function Resolve-AdcsColumnName {
    # Returns the first candidate name that actually exists in the discovered schema.
    param(
        [System.Collections.Generic.List[string]]$SchemaNames,
        [string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        foreach ($schemaName in $SchemaNames) {
            if ($schemaName -ieq $candidate) {
                return $schemaName
            }
        }
    }

    return $null
}

function Get-CertificateTemplateMap {
    # Builds a lookup table (both cn -> displayName and OID -> displayName) so the
    # CA's raw CertificateTemplate value (which may be a name or an OID depending on
    # CA/template version) can be resolved to the friendly template display name.
    [CmdletBinding()]
    param()

    $map = @{}

    try {
        $rootDse       = [ADSI]"LDAP://RootDSE"
        $configContext = $rootDse.configurationNamingContext
        $templatesPath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configContext"
        $templatesContainer = [ADSI]$templatesPath

        $searcher = New-Object System.DirectoryServices.DirectorySearcher($templatesContainer)
        $searcher.Filter = "(objectClass=pKICertificateTemplate)"
        $searcher.PageSize = 1000
        [void]$searcher.PropertiesToLoad.Add('cn')
        [void]$searcher.PropertiesToLoad.Add('displayName')
        [void]$searcher.PropertiesToLoad.Add('msPKI-Cert-Template-OID')

        foreach ($result in $searcher.FindAll()) {
            $cn          = if ($result.Properties['cn'].Count -gt 0) { $result.Properties['cn'][0] } else { $null }
            $displayName = if ($result.Properties['displayName'].Count -gt 0) { $result.Properties['displayName'][0] } else { $cn }
            $oid         = if ($result.Properties['msPKI-Cert-Template-OID'].Count -gt 0) { $result.Properties['msPKI-Cert-Template-OID'][0] } else { $null }

            if ($cn -and -not $map.ContainsKey($cn)) { $map[$cn] = $displayName }
            if ($oid -and -not $map.ContainsKey($oid)) { $map[$oid] = $displayName }
        }
    }
    catch {
        Write-Warning "Could not query Active Directory for certificate template display names; templates will be shown as returned by the CA (name or OID). $_"
    }

    return $map
}

# ---------------------------------------------------------------------------
# PROCESSING STARTS HERE
# ---------------------------------------------------------------------------

# Set up certdog
Set-ApiUrl -url $certdogApiUrl
Set-ApiToken -authToken $certdogApiToken

# ---------------------------------------------------------------------------
# Connect to the CA
# ---------------------------------------------------------------------------
Write-Verbose "Connecting to CA: $caConfig"

try {
    $caView = New-Object -ComObject CertificateAuthority.View
    $caView.OpenConnection($caConfig)
}
catch {
    throw "Failed to connect to CA '$caConfig'. $_"
}

# ---------------------------------------------------------------------------
# Resolve real schema column names for each field we need. Candidate lists are
# tried in order; the first name that actually exists in this CA's schema wins.
# ---------------------------------------------------------------------------
$schemaNames = Get-AdcsSchemaColumnNames -CaView $caView
Write-Verbose "CA schema exposes $($schemaNames.Count) columns."

$columnCandidates = [ordered]@{
    RequestID           = @('RequestID', 'Request.RequestID')
    RawCertificate       = @('RawCertificate', 'Request.RawCertificate')
    RawRequest           = @('RawRequest', 'Request.RawRequest')
    CertificateTemplate  = @('CertificateTemplate', 'Request.CertificateTemplate')
    RequesterName        = @('RequesterName', 'Request.RequesterName')
    Disposition          = @('Request.Disposition', 'Disposition')
    RevokedWhen          = @('Request.RevokedWhen', 'RevokedWhen')
    RevokedReason        = @('Request.RevokedReason', 'RevokedReason')
    NotBefore            = @('NotBefore', 'CertificateNotBefore', 'Request.NotBefore')
}

$resolvedName    = @{}   # concept -> actual schema column name used
$nameToConcept   = @{}   # actual schema column name -> concept (for row parsing)
$columnIndex     = @{}   # concept -> column index

$caView.SetResultColumnCount($columnCandidates.Count)

foreach ($concept in $columnCandidates.Keys) {
    $actualName = Resolve-AdcsColumnName -SchemaNames $schemaNames -Candidates $columnCandidates[$concept]

    if (-not $actualName) {
        Write-Warning "Could not find a matching schema column for '$concept' (tried: $($columnCandidates[$concept] -join ', ')). It will be skipped."
        continue
    }

    try {
        $idx = $caView.GetColumnIndex($CVRC_COLUMN_SCHEMA, $actualName)
        $caView.SetResultColumn($idx)
        $resolvedName[$concept]        = $actualName
        $columnIndex[$concept]         = $idx
        $nameToConcept[$actualName]    = $concept
        Write-Verbose "Resolved '$concept' -> '$actualName' (index $idx)"
    }
    catch {
        Write-Warning "Column '$actualName' resolved for '$concept' but GetColumnIndex/SetResultColumn failed: $_"
    }
}

# ---------------------------------------------------------------------------
# Restrict to certificates issued in the last N days (NotBefore >= startDate)
# ---------------------------------------------------------------------------
$startDate = (Get-Date).Date.AddDays(-$lastDays)

if ($columnIndex.ContainsKey('NotBefore')) {
    $caView.SetRestriction($columnIndex['NotBefore'], $CVR_SEEK_GE, $CVR_SORT_NONE, $startDate)
}
else {
    Write-Warning "Could not restrict by NotBefore date; returning all rows in the database."
}

# ---------------------------------------------------------------------------
# Build OID/name -> friendly display name map for certificate templates
# ---------------------------------------------------------------------------
$templateMap = Get-CertificateTemplateMap

# ---------------------------------------------------------------------------
# Iterate results
# ---------------------------------------------------------------------------
$rowObj  = $caView.OpenView()
$results = New-Object System.Collections.Generic.List[object]

while ($rowObj.Next() -ne -1) {

    $colObj = $rowObj.EnumCertViewColumn()

    $data = [ordered]@{
        RequestID           = $null
        RawCertificateB64   = $null
        RawRequestB64       = $null
        CertificateTemplate = $null
        RequesterName       = $null
        Disposition         = $null
        RevokedWhen         = $null
        RevokedReason       = $null
    }

    while ($colObj.Next() -ne -1) {
        $colName = $colObj.GetName()
        $concept = $nameToConcept[$colName]

        switch ($concept) {
            'RequestID'           { $data.RequestID           = $colObj.GetValue(0) }
            'RawCertificate'      { $data.RawCertificateB64   = Get-Base64ColumnValue $colObj 'RawCertificate' }
            'RawRequest'          { $data.RawRequestB64       = Get-Base64ColumnValue $colObj 'RawRequest' }
            'CertificateTemplate' { $data.CertificateTemplate = $colObj.GetValue(0) }
            'RequesterName'       { $data.RequesterName       = $colObj.GetValue(0) }
            'Disposition'         { $data.Disposition         = $colObj.GetValue(0) }
            'RevokedWhen'         { $data.RevokedWhen         = $colObj.GetValue(0) }
            'RevokedReason'       { $data.RevokedReason       = $colObj.GetValue(0) }
        }
    }

    Write-Verbose ("RequestID {0}: RawCertificate={1} chars, RawRequest={2} chars" -f `
        $data.RequestID, `
        $(if ($data.RawCertificateB64) { $data.RawCertificateB64.Length } else { 0 }), `
        $(if ($data.RawRequestB64) { $data.RawRequestB64.Length } else { 0 }))

    # Skip rows that never resulted in an issued certificate (pending / denied / failed requests)
    if ([string]::IsNullOrWhiteSpace($data.RawCertificateB64)) {
        continue
    }

    # NOTE: Request.Disposition is generally NOT updated when a certificate is revoked
    # after issuance on most AD CS versions - it typically stays at 20 (Issued). The
    # reliable signal is RevokedReason: AD CS writes the sentinel value -1 into this
    # column for certificates that have never been revoked (0 is a legitimate reason -
    # "Unspecified" - so it must NOT be treated as "not revoked"). We treat any
    # RevokedReason other than -1/$null as proof of revocation, and additionally OR in
    # Disposition -eq 21 for CA versions/configurations that do update it.
    $revokedReasonInt = $null
    if ($null -ne $data.RevokedReason -and "$($data.RevokedReason)" -ne '') {
        try { $revokedReasonInt = [int]$data.RevokedReason } catch { $revokedReasonInt = $null }
    }

    $isRevoked = (($null -ne $revokedReasonInt) -and ($revokedReasonInt -ne -1)) -or ($data.Disposition -eq 21)

    Write-Verbose ("RequestID {0}: Disposition={1}, RevokedReason(raw)={2}, RevokedWhen(raw)={3}, isRevoked={4}" -f `
        $data.RequestID, $data.Disposition, $data.RevokedReason, $data.RevokedWhen, $isRevoked)

    $revokedWhenOut   = $null
    $revokedReasonOut = $null
    if ($isRevoked) {
       if ($data.RevokedWhen) {
            try {
                $revokedWhenOut = ([datetime]$data.RevokedWhen).ToString('yyyy-MM-ddTHH:mm:ss')
            }
            catch {
                Write-Verbose "Could not format RevokedWhen value '$($data.RevokedWhen)' as a date: $_"
                $revokedWhenOut = $data.RevokedWhen
            }
        }
        if ($null -ne $revokedReasonInt -and $RevocationReasonMap.ContainsKey($revokedReasonInt)) {
            $revokedReasonOut = $RevocationReasonMap[$revokedReasonInt]
        }
        else {
            $revokedReasonOut = $data.RevokedReason
        }
    }

    $dispositionText = if ($DispositionMap.ContainsKey([int]$data.Disposition)) {
        $DispositionMap[[int]$data.Disposition]
    }
    else {
        "Unknown ($($data.Disposition))"
    }

    $templateOut = $data.CertificateTemplate
    if ($templateOut -and $templateMap.ContainsKey($templateOut)) {
        $templateOut = $templateMap[$templateOut]
    }

    try {
        $id = $data.RequestID
        Write-Host "Importing Request ID $id..."
        $certData = ConvertTo-Pem -Base64 $data.RawCertificateB64 -Label 'CERTIFICATE'
        $csrData  = ConvertTo-Pem -Base64 $data.RawRequestB64 -Label 'CERTIFICATE REQUEST'
        Import-certificate -certData $certData -ownerId $certdogOwnerUserId -teamId $certdogOwnerTeamId `
                           -revoked:$isRevoked -revocationTime $revokedWhenOut -revocationReason $revokedReasonOut `
                           -csrData $csrData -certIssuerId $certdogCertIssuerId -extraInfo $certdogExtraInfo `
                           -msTemplateName $templateOut > $null
        Write-Host "Imported OK"
    }
    catch {
        Write-Warning "Error details: $_"
    }
}
