<#
.SYNOPSIS
    Connects to a list of TLS end points, imports the certificates they present into
    certdog and (optionally) produces an HTML report of the results.

.DESCRIPTION
    For each end point:
      - A TLS connection is made and the certificate(s) presented by the server obtained.
        Certificates are obtained regardless of whether they are trusted, expired or
        issued for a different name, so that problem certificates are still discovered
      - Each certificate is imported into certdog with Import-Certificate. If certdog
        already holds the certificate (409 Conflict) the existing certificate id is taken
        from the error and its details retrieved with Get-Cert
      - The certificate id, subject, serial number and expiry are written out

    Failures (cannot connect, no certificates returned, import failed) are written out
    and included in the report.

    All output is written with Write-Host so that it is captured in the certdog logs.

    Requires the certdog PowerShell module (certdog-module.psm1) to be in the same
    directory as this script, or the current directory.

.PARAMETER apiToken
    The certdog API bearer token.

.PARAMETER apiUrl
    Optional. Base URL to the certdog API, e.g. https://certdog.example.com/certdog/api
    If not provided, the certdog module determines the URL itself (from apiurl.conf
    or the registry).

.PARAMETER htmlFile
    Optional. Full path of the HTML report to generate. If not provided no report is
    generated.

.PARAMETER htmlReportTitle
    Optional. The title of the HTML report. Defaults to "Certificate End Point Scan".

.PARAMETER cssFile
    Optional. A CSS stylesheet for the HTML report, so its formatting and colours can be
    defined by the user. When provided, the report links to this stylesheet rather than
    using the built-in styles. It may be:
      - A path relative to the HTML report, e.g. "report.css" (the usual choice when the
        report is served by a web server - place the CSS alongside the report)
      - A full path, e.g. "C:\certdog\styles\report.css" (linked as a file:/// URL,
        so only works when the report is opened directly from disk)
      - A URL, e.g. "https://intranet.example.com/styles/report.css"
    If a relative or full path is given and the file does not exist, it is created
    containing the default styles, as a starting point for editing. An existing file is
    never overwritten. See report.css in this folder for the classes that can be styled.

.PARAMETER endPoints
    The end points to scan, e.g. 'google.com', 'krestfield.com:8443'. Port 443 is used
    if no port is specified. A URL may also be given (e.g. https://krestfield.com/path).
    A single comma separated string (e.g. "google.com,krestfield.com") or a list written
    as "['google.com', 'krestfield.com']" are also accepted, for when the script is
    called with -File and arrays cannot be passed.

.PARAMETER ownerId
    Optional. The id of the user to assign discovered certificates to.

.PARAMETER teamId
    Optional. The id of the team to assign discovered certificates to.

.PARAMETER extraInfo
    Optional. Extra information to store with discovered certificates.

.PARAMETER includeChain
    Switch. By default only the end point (server) certificate is imported. If provided,
    the issuing CA certificates in the chain are imported as well.

.PARAMETER timeoutSeconds
    Optional. Connection timeout in seconds for each end point. Defaults to 10.

.PARAMETER expiringSoonDays
    Optional. Certificates expiring within this many days are reported as
    "OK - Expiring Soon". Defaults to 30.

.EXAMPLE
    .\Get-EndpointCertificates.ps1 -apiToken "eyJhbGciOi..." -endPoints 'google.com', 'krestfield.com'

.EXAMPLE
    .\Get-EndpointCertificates.ps1 -apiToken "eyJhbGciOi..." -apiUrl "https://certdog.local/certdog/api" `
        -endPoints 'google.com', 'krestfield.com:8443' -teamId "6a7dda093203323798ccfd00" `
        -htmlFile "C:\reports\daily-url-check.html" -htmlReportTitle "Daily Company URL Check"

.EXAMPLE
    .\Get-EndpointCertificates.ps1 -apiToken "eyJhbGciOi..." -endPoints 'google.com', 'krestfield.com' `
        -htmlFile "C:\certdog\tomcat\webapps\certdog#reports\index.html" -cssFile "report.css"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$apiToken,

    [string]$apiUrl,

    [string]$htmlFile,

    [string]$htmlReportTitle = 'Certificate End Point Scan',

    [string]$cssFile,

    [Parameter(Mandatory = $true)]
    [string[]]$endPoints,

    [string]$ownerId,

    [string]$teamId,

    [string]$extraInfo,

    [switch]$includeChain,

    [int]$timeoutSeconds = 10,

    [int]$expiringSoonDays = 30
)

$ErrorActionPreference = 'Stop'

# --- Load the certdog module ---------------------------------------------

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath 'certdog-module.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    $modulePath = '.\certdog-module.psm1'
}

try {
    Import-Module $modulePath -Force
}
catch {
    Write-Host "ERROR: Unable to load certdog-module.psm1: $($_.Exception.Message)"
    exit 1
}

# Only override the API URL if one was supplied - otherwise the module works it out
if ($apiUrl) {
    # Trim any trailing slash from the API URL so we don't end up with double slashes
    certdog-module\Set-ApiUrl -url $apiUrl.TrimEnd('/')
}
certdog-module\Set-ApiToken -authToken $apiToken

# The system URL is used to build the links to each certificate in the report
$systemUrl = $null
try {
    $settings = certdog-module\Get-Settings
    if ($settings.systemUrl) {
        $systemUrl = ([string]$settings.systemUrl).TrimEnd('/')
    }
    else {
        Write-Host "No systemUrl returned in the certdog settings. Report links will not be generated"
    }
}
catch {
    Write-Host "Unable to obtain the certdog settings (report links will not be generated): $($_.Exception.Message)"
}

# --- Helper functions ------------------------------------------------------

# Accepts end points as passed directly (an array) or as a single string such as
# "google.com,krestfield.com" or "['google.com', 'krestfield.com']"
function Get-EndPointList {
    param([string[]]$Values)

    foreach ($value in $Values) {
        foreach ($part in ($value -split '[,;\s]+')) {
            $part = $part.Trim().Trim('[', ']', '"', "'")
            if ($part) { $part }
        }
    }
}

# Splits an end point (host, host:port or a URL) into its host and port
function Get-HostAndPort {
    param([string]$EndPoint)

    $uri = $null
    $toParse = if ($EndPoint -match '^[a-z][a-z0-9+.-]*://') { $EndPoint } else { "https://$EndPoint" }
    if (-not [System.Uri]::TryCreate($toParse, [System.UriKind]::Absolute, [ref]$uri) -or -not $uri.Host) {
        throw "'$EndPoint' is not a valid end point"
    }

    $port = if ($uri.IsDefaultPort -or $uri.Port -lt 1) { 443 } else { $uri.Port }

    [pscustomobject]@{
        Host = $uri.Host.Trim('[', ']')   # Uri wraps IPv6 addresses in brackets
        Port = $port
    }
}

# Makes a TLS connection to the end point and returns the certificates presented,
# server certificate first. Throws if the connection cannot be made.
function Get-EndPointCertificates {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutSeconds,
        [bool]$IncludeChain
    )

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $sslStream = $null
    try {
        $connectTask = $tcpClient.ConnectAsync($HostName, $Port)
        if (-not $connectTask.Wait($TimeoutSeconds * 1000)) {
            throw "Timed out after $TimeoutSeconds seconds"
        }
        $tcpClient.ReceiveTimeout = $TimeoutSeconds * 1000
        $tcpClient.SendTimeout = $TimeoutSeconds * 1000

        # Accept any certificate - we want to discover expired, untrusted or mis-named
        # certificates too. The chain is copied here as it is reset once the callback returns.
        $captured = @{ Chain = @() }
        $callback = {
            param($s, $certificate, $chain, $sslPolicyErrors)
            if ($chain -and $chain.ChainElements) {
                $captured.Chain = @($chain.ChainElements | ForEach-Object {
                    New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $_.Certificate.RawData)
                })
            }
            return $true
        }.GetNewClosure()

        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false,
            [System.Net.Security.RemoteCertificateValidationCallback]$callback)

        # SslProtocols None lets the operating system choose the protocol versions
        $sslStream.AuthenticateAsClient($HostName, $null, [System.Security.Authentication.SslProtocols]::None, $false)

        if (-not $sslStream.RemoteCertificate) {
            return @()
        }

        $serverCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $sslStream.RemoteCertificate.GetRawCertData())
        $certs = @($serverCert)

        if ($IncludeChain) {
            $certs += @($captured.Chain | Where-Object { $_.Thumbprint -ne $serverCert.Thumbprint })
        }

        return $certs
    }
    catch {
        # Report the innermost error, which is the most useful (e.g. "No such host is known")
        $ex = $_.Exception
        while ($ex.InnerException) { $ex = $ex.InnerException }
        throw $ex.Message
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        $tcpClient.Dispose()
    }
}

function ConvertTo-PemCertificate {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $base64 = [System.Convert]::ToBase64String($Certificate.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN CERTIFICATE-----`n$($base64 -replace "`r`n", "`n")`n-----END CERTIFICATE-----"
}

# When an API call fails, the certdog module throws the parsed JSON response body
# (e.g. @{ status = 409; error = 'Conflict'; message = '...' }) rather than the original
# web error. Returns that body if this error is one of those, otherwise $null.
function Get-ErrorResponseObject {
    param($ErrorRecord)

    $target = $ErrorRecord.TargetObject
    if ($target -is [psobject] -and -not ($target -is [string]) -and
        ($target.PSObject.Properties['status'] -or $target.PSObject.Properties['message'])) {
        return $target
    }
    return $null
}

# Collects all of the text available for an error (message and any response body)
function Get-ErrorText {
    param($ErrorRecord)

    $parts = @()
    $response = Get-ErrorResponseObject -ErrorRecord $ErrorRecord
    if ($response -and $response.message) {
        $parts += [string]$response.message
    }
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $parts += $ErrorRecord.ErrorDetails.Message
    }
    $parts += $ErrorRecord.Exception.Message
    $parts += $ErrorRecord.ToString()
    return ($parts | Where-Object { $_ } | Select-Object -Unique) -join ' '
}

# Gets the HTTP status code from an error, if there is one
function Get-ErrorStatusCode {
    param($ErrorRecord)

    $response = Get-ErrorResponseObject -ErrorRecord $ErrorRecord
    if ($response -and $response.status) {
        try { return [int]$response.status } catch { }
    }

    try {
        if ($ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.StatusCode) {
            return [int]$ErrorRecord.Exception.Response.StatusCode
        }
    }
    catch { }
    return $null
}

# Returns an error message suitable for display - the message from the API response
# body if there is one, otherwise the exception message
function Get-ErrorMessage {
    param($ErrorRecord)

    $response = Get-ErrorResponseObject -ErrorRecord $ErrorRecord
    if ($response) {
        if ($response.message) { return [string]$response.message }
        if ($response.error) { return "$($response.status) $($response.error)" }
    }

    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        try {
            $body = $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json
            if ($body.message) { return $body.message }
        }
        catch { }
        return $ErrorRecord.ErrorDetails.Message
    }
    return $ErrorRecord.Exception.Message
}

# Imports the certificate into certdog. If it is already present, retrieves the existing
# certificate instead. Returns the certdog certificate and whether it was newly imported.
function Import-EndPointCertificate {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    # ownerId and teamId are mandatory parameters of the module's Import-Certificate, so
    # are always passed - as empty strings when not set, which certdog treats as not provided
    $importParams = @{
        certData = (ConvertTo-PemCertificate -Certificate $Certificate)
        ownerId  = if ($ownerId) { $ownerId } else { '' }
        teamId   = if ($teamId) { $teamId } else { '' }
    }
    if ($extraInfo) { $importParams.extraInfo = $extraInfo }

    try {
        # 6>$null hides the module's own "Import-Certificate failed" output (which it writes
        # for every 409). Any error is reported below instead.
        $cert = certdog-module\Import-Certificate @importParams 6>$null
        return [pscustomobject]@{ Cert = $cert; IsNew = $true }
    }
    catch {
        $errorText = Get-ErrorText -ErrorRecord $_
        $statusCode = Get-ErrorStatusCode -ErrorRecord $_
        $isConflict = ($statusCode -eq 409) -or ($errorText -match '409|Conflict|already present in the system')

        # The service returns: "The certificate is already present in the system. Details: id: <id>, owner: ..."
        $idMatch = [regex]::Match($errorText, '(?i)already present in the system.*?\bid:\s*([^,\s"\\]+)')
        if (-not $isConflict -or -not $idMatch.Success) {
            throw "Import failed. Error: $(Get-ErrorMessage -ErrorRecord $_)"
        }
    }

    $existingId = $idMatch.Groups[1].Value
    try {
        $cert = certdog-module\Get-Cert -id $existingId
    }
    catch {
        throw "Certificate already present in certdog (id: $existingId) but its details could not be retrieved. Error: $(Get-ErrorMessage -ErrorRecord $_)"
    }
    return [pscustomobject]@{ Cert = $cert; IsNew = $false }
}

function Get-CertStatus {
    param([datetime]$ValidTo)

    $now = Get-Date
    if ($ValidTo -lt $now) { return 'FAIL - Expired' }
    if ($ValidTo -lt $now.AddDays($expiringSoonDays)) { return 'OK - Expiring Soon' }
    return 'OK'
}

# --- Scan the end points ---------------------------------------------------

$results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param($EndPoint, $Info, $Subject = '', $SerialNumber = '', $ValidTo = '', $Status = 'FAIL', $CertId = $null)

    $results.Add([pscustomobject]@{
        EndPoint     = $EndPoint
        Info         = $Info
        Subject      = $Subject
        SerialNumber = $SerialNumber
        ValidTo      = $ValidTo
        Status       = $Status
        CertId       = $CertId
    })
}

$endPointList = @(Get-EndPointList -Values $endPoints)
if ($endPointList.Count -eq 0) {
    Write-Host "ERROR: No end points were provided"
    exit 1
}

foreach ($endPoint in $endPointList) {
    Write-Host ""
    Write-Host "Checking end point: $endPoint"

    try {
        $target = Get-HostAndPort -EndPoint $endPoint
    }
    catch {
        Write-Host "Failed to connect to end point: $endPoint. Error: $($_.Exception.Message)"
        Add-Result -EndPoint $endPoint -Info "Failed to connect. Error: $($_.Exception.Message)"
        continue
    }

    try {
        $certs = @(Get-EndPointCertificates -HostName $target.Host -Port $target.Port `
                -TimeoutSeconds $timeoutSeconds -IncludeChain $includeChain.IsPresent)
    }
    catch {
        Write-Host "Failed to connect to end point: $endPoint. Error: $($_.Exception.Message)"
        Add-Result -EndPoint $endPoint -Info "Failed to connect. Error: $($_.Exception.Message)"
        continue
    }

    if ($certs.Count -eq 0) {
        Write-Host "Connected to end point $endPoint but no certificates were returned"
        Add-Result -EndPoint $endPoint -Info 'Connected but no certificates were returned'
        continue
    }

    Write-Host "Connected to end point $endPoint. $($certs.Count) certificate(s) returned"

    foreach ($x509 in $certs) {
        try {
            $imported = Import-EndPointCertificate -Certificate $x509
        }
        catch {
            $message = $_.Exception.Message
            Write-Host "  Certificate $($x509.Subject) (serial number: $($x509.SerialNumber)): $message"
            Add-Result -EndPoint $endPoint -Info $message -Subject $x509.Subject `
                -SerialNumber $x509.SerialNumber -ValidTo $x509.NotAfter.ToString('dd MMMM yyyy')
            continue
        }

        $cert = $imported.Cert
        $info = if ($imported.IsNew) { 'New certificate discovered and imported' } else { 'Existing certificate' }

        $validToStr = if ($cert.validToStr) { $cert.validToStr } else { $x509.NotAfter.ToString('dd MMMM yyyy') }
        $status = Get-CertStatus -ValidTo $x509.NotAfter

        Write-Host "  $info"
        Write-Host "    Id:            $($cert.id)"
        Write-Host "    Subject:       $($cert.subjectDn)"
        Write-Host "    Serial Number: $($cert.serialNumber)"
        Write-Host "    Valid To:      $validToStr"
        Write-Host "    Status:        $status"

        Add-Result -EndPoint $endPoint -Info $info -Subject $cert.subjectDn -SerialNumber $cert.serialNumber `
            -ValidTo $validToStr -Status $status -CertId $cert.id
    }
}

# --- Summary -------------------------------------------------------------

$okCount = @($results | Where-Object { $_.Status -eq 'OK' }).Count
$expiringCount = @($results | Where-Object { $_.Status -eq 'OK - Expiring Soon' }).Count
$failCount = @($results | Where-Object { $_.Status -like 'FAIL*' }).Count

Write-Host ""
Write-Host "Scanned $($endPointList.Count) end point(s). Results: $okCount OK, $expiringCount OK - Expiring Soon, $failCount FAIL"

# --- HTML report -----------------------------------------------------------

# The default report styles. Used inline when -cssFile is not provided, and written to
# the CSS file as a starting point when -cssFile is provided but does not yet exist.
$defaultCss = @'
/* Styles for the certdog end point scan report */

body { font-family: "Segoe UI", Arial, sans-serif; margin: 24px; color: #222; }

/* Title and last run time */
.report-title { margin-bottom: 4px; }
.report-last-run { color: #555; margin-bottom: 16px; }

/* Results table */
.report-table { border-collapse: collapse; width: 100%; }
.report-table th,
.report-table td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; vertical-align: top; }
.report-table th { background: #f0f0f0; }

/* Columns: col-endpoint, col-info, col-subject, col-serial, col-validto, col-status, col-link */
.col-serial { font-family: Consolas, monospace; }

/* Status. Applied to both the row (tr) and the Status cell (td) */
td.status-ok { color: #1b6e20; font-weight: bold; }
td.status-expiring { color: #9a6700; font-weight: bold; }
td.status-fail { color: #b00020; font-weight: bold; }
'@

if ($htmlFile) {
    function ConvertTo-HtmlText {
        param($Value)
        return [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }

    $reportFolder = Split-Path -Path $htmlFile -Parent

    $styleTag = "<style>`n$defaultCss`n</style>"
    if ($cssFile) {
        if ($cssFile -match '^[a-z][a-z0-9+.-]*://') {
            # A URL - link to it as is
            $cssHref = $cssFile
            $cssPath = $null
        }
        elseif ([System.IO.Path]::IsPathRooted($cssFile)) {
            # A full path - browsers need a file:/// URL for this
            $cssHref = (New-Object System.Uri($cssFile, [System.UriKind]::Absolute)).AbsoluteUri
            $cssPath = $cssFile
        }
        else {
            # Relative to the report
            $cssHref = $cssFile -replace '\\', '/'
            $cssPath = if ($reportFolder) { Join-Path -Path $reportFolder -ChildPath $cssFile } else { $cssFile }
        }

        if ($cssPath -and -not (Test-Path -LiteralPath $cssPath)) {
            try {
                $cssFolder = Split-Path -Path $cssPath -Parent
                if ($cssFolder -and -not (Test-Path -LiteralPath $cssFolder)) {
                    New-Item -Path $cssFolder -ItemType Directory -Force | Out-Null
                }
                Set-Content -LiteralPath $cssPath -Value $defaultCss -Encoding UTF8
                Write-Host "CSS file $cssPath did not exist. Created it with the default styles"
            }
            catch {
                Write-Host "Unable to create the CSS file $cssPath. Error: $($_.Exception.Message)"
            }
        }

        $styleTag = "<link rel=`"stylesheet`" href=`"$(ConvertTo-HtmlText $cssHref)`">"
    }

    $rows = foreach ($result in $results) {
        $statusClass = switch ($result.Status) {
            'OK'                 { 'status-ok' }
            'OK - Expiring Soon' { 'status-expiring' }
            default              { 'status-fail' }
        }

        $link = ''
        if ($systemUrl -and $result.CertId) {
            $href = "$systemUrl/ui/#/certificates/certificatedetails/$($result.CertId)"
            $link = "<a href=`"$(ConvertTo-HtmlText $href)`" target=`"_blank`">Click</a>"
        }

        @"
      <tr class="$statusClass">
        <td class="col-endpoint">$(ConvertTo-HtmlText $result.EndPoint)</td>
        <td class="col-info">$(ConvertTo-HtmlText $result.Info)</td>
        <td class="col-subject">$(ConvertTo-HtmlText $result.Subject)</td>
        <td class="col-serial">$(ConvertTo-HtmlText $result.SerialNumber)</td>
        <td class="col-validto">$(ConvertTo-HtmlText $result.ValidTo)</td>
        <td class="col-status $statusClass">$(ConvertTo-HtmlText $result.Status)</td>
        <td class="col-link">$link</td>
      </tr>
"@
    }

    $title = ConvertTo-HtmlText $htmlReportTitle
    $lastRun = ConvertTo-HtmlText (Get-Date -Format 'dd MMMM yyyy HH:mm:ss')

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>$title</title>
  $styleTag
</head>
<body>
  <h1 class="report-title">$title</h1>
  <div class="report-last-run">Last Run: $lastRun</div>
  <table class="report-table">
    <thead>
      <tr>
        <th class="col-endpoint">End Point</th>
        <th class="col-info">Info</th>
        <th class="col-subject">Subject</th>
        <th class="col-serial">Serial Number</th>
        <th class="col-validto">Valid To</th>
        <th class="col-status">Status</th>
        <th class="col-link">Link</th>
      </tr>
    </thead>
    <tbody>
$($rows -join "`n")
    </tbody>
  </table>
</body>
</html>
"@

    try {
        if ($reportFolder -and -not (Test-Path -LiteralPath $reportFolder)) {
            New-Item -Path $reportFolder -ItemType Directory -Force | Out-Null
        }
        Set-Content -LiteralPath $htmlFile -Value $html -Encoding UTF8
        Write-Host "Report saved to: $htmlFile"
    }
    catch {
        Write-Host "ERROR: Unable to write the report to $htmlFile. Error: $($_.Exception.Message)"
        exit 1
    }
}

exit 0
