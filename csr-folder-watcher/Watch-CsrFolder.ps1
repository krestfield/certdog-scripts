<#
.SYNOPSIS
    Watches a directory for PKCS#10 CSR files, submits valid ones to the Certdog REST API,
    and files the results (issued certs, processed CSRs, failed files, logs).

.DESCRIPTION
    For every file found directly inside -watchDirectory:
      1. Attempts to parse it as a PKCS#10 CSR (via certutil -dump).
      2. If parsing fails      -> file is moved to <watchDirectory>\failed, logged.
      3. If parsing succeeds   -> DN and SANs are extracted (for logging), the CSR is POSTed
                                   to $apiUrl/certs/requestp10.
           - On success        -> issued cert saved to <watchDirectory>\issued\<name>.cer,
                                   original CSR moved to <watchDirectory>\processed, logged.
           - On API failure    -> original CSR moved to <watchDirectory>\failed, logged.

    A log file named <yyyyMMdd>.log is written/appended to <watchDirectory>\logs for each run.

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
    .\certdog-csr-watcher.ps1 -apiUrl "https://certdog.example.com/api" -apiToken "abcdef123456" `
        -watchDirectory "C:\certs" -issuerId "63f1..." -teamId "63f2..."

.NOTES
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
# CSR parsing helpers
# ---------------------------------------------------------------------------

# Runs certutil -dump against the file and returns the raw text output plus
# whether certutil considered it a valid request.
function Get-CsrDumpOutput {
    param([Parameter(Mandatory = $true)][string]$FilePath)

    $output = & certutil.exe -dump "$FilePath" 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String)

    $isValid = ($exitCode -eq 0) -and
               ($text -match 'PKCS10 Certificate Request') -and
               ($text -match 'CertUtil:\s*-dump command completed successfully')

    return [pscustomobject]@{
        IsValid = $isValid
        Text    = $text
    }
}

# Extracts a human-readable DN string from certutil -dump output.
function Get-DnFromDump {
    param([Parameter(Mandatory = $true)][string]$DumpText)

    $lines = $DumpText -split "`r?`n"
    $dnParts = @()
    $inSubject = $false

    foreach ($line in $lines) {
        if ($line -match '^\s*Subject:\s*$') {
            $inSubject = $true
            continue
        }
        if ($inSubject) {
            if ($line -match '^\s{2,}\S') {
                $trimmed = $line.Trim()
                if ($trimmed -notmatch '^Name Hash\s*\((sha1|md5)\)') {
                    $dnParts += $trimmed
                }
            }
            else {
                break
            }
        }
    }

    if ($dnParts.Count -gt 0) {
        return ($dnParts -join ', ')
    }
    return '(unknown DN)'
}

# Extracts SAN entries from certutil -dump output, formatted like:
# DNS:server2.local.com, IP:10.2.34.4
function Get-SansFromDump {
    param([Parameter(Mandatory = $true)][string]$DumpText)

    $lines = $DumpText -split "`r?`n"
    $inSan = $false
    $sans = @()

    foreach ($line in $lines) {
        if ($line -match 'Subject Alternative Name') {
            $inSan = $true
            continue
        }

        if ($inSan) {
            if ($line -match '^\s{2,}\S') {
                $trimmed = $line.Trim()
                switch -Regex ($trimmed) {
                    '^DNS Name=(.+)$'          { $sans += "DNS:$($Matches[1])"; continue }
                    '^IPv4 Address=(.+)$'      { $sans += "IP:$($Matches[1])"; continue }
                    '^IPv6 Address=(.+)$'      { $sans += "IP:$($Matches[1])"; continue }
                    '^RFC822 Name=(.+)$'       { $sans += "EMAIL:$($Matches[1])"; continue }
                    '^URL=(.+)$'               { $sans += "URI:$($Matches[1])"; continue }
                    '^Directory Address'       { continue }
                    default {
                        # Stop once we hit a line that's clearly a new extension/section,
                        # otherwise keep it as a generic entry.
                        if ($trimmed -match '^\d+(\.\d+)+:') { $inSan = $false }
                        else { $sans += $trimmed }
                    }
                }
            }
            else {
                $inSan = $false
            }
        }
    }

    if ($sans.Count -gt 0) {
        return ($sans -join ', ')
    }
    return '(none)'
}

# Reads the CSR file and returns just the base64 payload (no PEM headers/footers,
# no line breaks), regardless of whether the source file was PEM or raw DER.
function Get-CsrBase64 {
    param([Parameter(Mandatory = $true)][string]$FilePath)

    $rawText = Get-Content -LiteralPath $FilePath -Raw -ErrorAction Stop

    if ($rawText -match '-----BEGIN [^-]*REQUEST-----') {
        $b64 = $rawText -replace '-----BEGIN [^-]*REQUEST-----', '' `
                         -replace '-----END [^-]*REQUEST-----', '' `
                         -replace '\s', ''
        return $b64
    }
    else {
        # Assume raw DER bytes
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        return [System.Convert]::ToBase64String($bytes)
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

    $dump = Get-CsrDumpOutput -FilePath $fullPath

    if (-not $dump.IsValid) {
        $destination = Join-Path $failedDir $file.Name
        Move-Item -LiteralPath $fullPath -Destination $destination -Force
        Write-Log "File: $fullPath was not processed as the file was not a valid CSR. File moved to the failed folder."
        continue
    }

    $dn   = Get-DnFromDump -DumpText $dump.Text
    $sans = Get-SansFromDump -DumpText $dump.Text

    try {
        $csrBase64 = Get-CsrBase64 -FilePath $fullPath
    }
    catch {
        $destination = Join-Path $failedDir $file.Name
        Move-Item -LiteralPath $fullPath -Destination $destination -Force
        Write-Log "File: $fullPath was not processed as the file was not a valid CSR. File moved to the failed folder."
        continue
    }

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

        Write-Log "File: $fullPath was processed OK. Request was for DN: $dn and included SANs $sans The certificate has been saved to $certPath"
    }
    else {
        $errMsg = if ($result.Error) { $result.Error } else { 'No error detail returned by Certdog.' }

        # ASSUMPTION: move CSRs that failed to issue into \failed so they are not
        # reprocessed on the next run. Remove this Move-Item call if you'd rather
        # leave them in watchDirectory for a retry.
        $destination = Join-Path $failedDir $file.Name
        Move-Item -LiteralPath $fullPath -Destination $destination -Force

        Write-Log "File: $fullPath was a valid CSR but a certificate could not be issued. $errMsg"
    }
}
