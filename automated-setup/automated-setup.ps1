<# 
 # Install and Setup Script
 # ------------------------
 #
 # This script will install certdog 1.8 and configure a root and intermediate CA with a TLS certificate profile
 # CRL and OCSP services, leaving a system that is ready to issue certificates
 #
 # The Root and Intermediate CA certificates are installed into the local machine store
 #
 # Steps:
 #   1. Update the parameters below if required
 #   2. Open a PowerShell window as Administrator and run .\automated-setup.ps1
 #>

# #############################################################################
# Update these parameters
# #############################################################################
$dbPassword='password'
$adminUsername='admin'
$adminEmail='admin@nowhere.com'
$adminPassword='password'
$keystorePassword='password'

# Root CA Details
$rootCaConfigName = "Certdog Test Root CA"
$rootCaConfigDn = "CN=Certdog Test Root CA,O=Krestfield"

# Intermediate CA Details
$intCaConfigName = "Certdog Test Issuing CA"
$intCaConfigDn = "CN=Certdog Test Issuing CA,O=Krestfield"
# #############################################################################
# #############################################################################
$installDir = "C:\certdogfree"
$issuerName = "Certdog TLS Issuer"

<#
.Synopsis
   Downloads certdog
.DESCRIPTION
   Obtains the free certdog zip, downloads and unzips to c:\certdogfree
.EXAMPLE
   Download-Certdog
#>
Function Download-Certdog
{
    # Download the installer
    Write-Host "`nDownloading certdog..."
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile('https://krestfield.s3.eu-west-2.amazonaws.com/certdog/certdogfree_v190.zip', 'c:\certdog.zip')

    # Extract the zip
    cd \
    Expand-Archive .\certdog.zip -DestinationPath .
}

<#
.Synopsis
   Installs certdog
.DESCRIPTION
   Installs the VC runtime as required by certdog
   Installs the free version of certdog to c:\certdogfree using the parameters provided at the top of this script
   Imports the default test SSL root certificate, so there are no SSL errors when opening the UI via a browser
.EXAMPLE
   Install-Certdog
#>
Function Install-Certdog
{
    # Install - first install the Visual C++ requirement, then certdog using the parameters from above
    cd certdogfree\install
    .\VC_redist.x64.exe /install /quiet | Out-Null
    .\install.ps1 -acceptEula -dbAdminPassword $dbPassword -firstAdminUsername $adminUsername -firstAdminEmail $adminEmail -firstAdminPassword $adminPassword -listeningIpAddress 0.0.0.0 -listeningPort 443 -installAdcsAgent

    # Install the test root certificate to avoid local SSL errors
    # NOTE: This should be removed from the local trust store once a new SSL cert has been installed
    Import-Certificate -FilePath "$($installDir)\config\sslcerts\dbssl_root.cer" -CertStoreLocation Cert:\LocalMachine\Root
}

<#
.Synopsis
   Configures certdog
.DESCRIPTION
   Set the CA DNs and names from the parameters at the top of this script
   Configures the following in certdog:
     Creates a software keystore - the password for which is provided at the top of this script
     Creates a root CA with CRL configured
        Saves the root CA cert to file
     Creates an Issuing/Intermediate CA from the root, with CRL and OCSP services configured
        Saves the issuing CA cert to file
     Creates a certificate profile with key usage set to client and server authentication for TLS
     Creates a certificate issuer from the above profile and issuing CA
     Creates a CSR generator
     Adds this issuer as an authorised issuer to the Admin group    
.EXAMPLE
   Install-Certdog
#>
Function Configure-Certdog
{
    cd \certdogfree\bin

    Import-Module .\certdog-module.psm1

    login -username $adminUsername -password $adminPassword

    $keyStore = Add-SoftwareKeyStore -name "Software KeyStore" -password $keystorePassword

    # Machine details
    $hostDetails = [System.Net.Dns]::GetHostByName($env:computerName)
    $fqdn = $hostDetails.HostName
    $cdpUrl = "http://$($fqdn)/certdog/crl/rootca.crl"

    # Create the test CA
    $caConfigName = "Certdog Test Root CA"
    $caConfigDn = "CN=Certdog Test Root CA,O=Krestfield"
    $ca = Add-LocalCAConfig -name $rootCaConfigName -signatureAlgorithm RSA -keySize 4096 -hashAlgorithm SHA256 -rootCa `
                            -keyStoreId $keyStore.id -subjectDn $rootCaConfigDn -lifetimeInDays 3650 `
                            -generateCrls -crlLifetimeMinutes 43800 -crlGenerationMinutes 60 `
                            -crlFilename "C:\certdogfree\tomcat\crlwebapps\certdog#crl\rootca.crl" -cdps @($cdpUrl) `
                            -policies @("User Notice|1.3.6.1.4.1.33528.1.2.100.1|For test purposes only")
    $cert = $ca.caCertificate
    New-Item -Path $installDir -Name "certs" -ItemType "directory"
    Set-Content -Path "$($installDir)\certs\rootCert.cer" -Value $cert

    $intCaConfigName = "Certdog Test Issuing CA"
    $intCaConfigDn = "CN=Certdog Test Issuing CA,O=Krestfield"
    Write-Host "Creating Intermediate CA..."
    $cdpUrl = "http://$($fqdn)/certdog/crl/issuingca.crl"
    $ocspUrl = "http://$($fqdn)/certdog/ocsp"
    $intCa = Add-LocalCAConfig -name $intCaConfigName -issuerId $ca.id -keyStoreId $keyStore.id `
                               -signatureAlgorithm RSA -keySize 2048 -hashAlgorithm SHA256 `
                               -subjectDn $intCaConfigDn -lifetimeInDays 3650 `
                               -generateCrls -crlLifetimeMinutes 4320 -crlGenerationMinutes 15 `
                               -crlFilename "C:\certdogfree\tomcat\crlwebapps\certdog#crl\issuingca.crl" -cdps @($cdpUrl) -aiaOcspUrls @($ocspUrl) `
                               -policies @("User Notice|1.3.6.1.4.1.33528.1.2.100.1|For test purposes only")
    $intCert = $intCa.caCertificate
    Set-Content -Path "$($installDir)\certs\intCert.cer" -Value $intCert

    $ocspServer = Set-OCSPForLocalCA -id $intCa.id

    # Create the TLS cert profile
    $tlsProfileName = "TLS Profile"
    $tlsProfile = Add-LocalCACertProfile -name $tlsProfileName -lifetimeInMinutes 129600 -includeSansFromCsr $true -enhancedKeyUsages @('clientAuth', 'serverAuth') -keyUsages @('digitalSignature','keyEncipherment')

    # Create TLS cert issuer
    $certIssuerName = $issuerName
    $tlsCertIssuer = Add-LocalCA -caName $certIssuerName -localCaConfigId $intCa.id -certProfileId $tlsProfile.id

    # Create a CSR Generator
    $csrGenerator = Add-CsrGenerator -name "RSA2048 Generator" -signatureAlgorithm RSA -keySize 2048 -hashAlgorithm SHA256

    # Add to Admin Team as authorised CAs
    $team = team -name "Admin Team"
    $updatedTeam = Update-Team -id $team.id -authorisedCas @($codeSignCertIssuer.id, $tlsCertIssuer.id)

    logout
}

<#
.Synopsis
   Imports the CA certificates
.DESCRIPTION
   Imports the certificates that were saved to file in the above function to the windows local machine store
.EXAMPLE
   Import-Certs
#>
Function Import-Certs
{
    # Remove the module and call the native Import-Certificate to import the CA certs to the machine store
    Remove-Module -Name certdog-module
    Import-Certificate -FilePath "$($installDir)\certs\rootCert.cer" -CertStoreLocation Cert:\LocalMachine\Root
    Import-Certificate -FilePath "$($installDir)\certs\intCert.cer" -CertStoreLocation Cert:\LocalMachine\CA
    Write-Host "The Root and CA certificates have been imported to the local certificate store. To publish to AD, use the following commands:"
    Write-Host "  certutil.exe -dspublish -f $installDir\certs\rootCert.cer RootCA"
    Write-Host "  certutil.exe -dspublish -f $installDir\certs\intCert.cer SubCA"
}

<#
.Synopsis
   Opens the certdog UI
.DESCRIPTION
   Starts a browser, navigating to the default certdog address using the MS Edge browser
.EXAMPLE
   Start-Browser
#>
Function Start-Browser
{
    [system.Diagnostics.Process]::Start("msedge","https://127.0.0.1/certdog")
}

# #############################################################################

<#
 #
 # Main Processing Starts Here
 #
 #>
Write-Host ""
Write-Host "Krestfield Certdog Automated Setup" -ForegroundColor Green
Write-Host "==================================" -ForegroundColor Green
Write-Host ""

Download-Certdog
Install-Certdog
Configure-Certdog
Import-Certs
Start-Browser

# #############################################################################
# #############################################################################

# SIG # Begin signature block
# MIIk6QYJKoZIhvcNAQcCoIIk2jCCJNYCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU1lyonmbhTfsLjt1zwhreJU+L
# w3Wggh7QMIIFZDCCBEygAwIBAgIRAM25j/9Lvs20l95S6qzivfkwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3Rl
# cjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSQw
# IgYDVQQDExtTZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0EwHhcNMjAwNTIwMDAw
# MDAwWhcNMjMwNTIwMjM1OTU5WjCBqTELMAkGA1UEBhMCR0IxETAPBgNVBBEMCEhQ
# MTMgNVVZMRgwFgYDVQQIDA9CdWNraW5naGFtc2hpcmUxFTATBgNVBAcMDEhpZ2gg
# V3ljb21iZTEcMBoGA1UECQwTNzkgTGl0dGxld29ydGggUm9hZDEbMBkGA1UECgwS
# S3Jlc3RmaWVsZCBMaW1pdGVkMRswGQYDVQQDDBJLcmVzdGZpZWxkIExpbWl0ZWQw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCo00r3I7IbUV+cRM5rij46
# vp9j89hIPS4q0cKauz/JLuUIAILUtSUVt9ANLxl45FbTwLSD/S9NXRAKcSejIzS/
# aadkE/taxIJ07fM1208MPrMKVA6EtmfbJ61c/LrZc0097n/oHzqPZHL06+7PoN0P
# 9OWoDF2o0xf5wOKT7ztnNjpfVUcR9QIZOGgqIK5Cdl0ZR/gYW2ZvlWQ3jAIsKQOJ
# m+8Pw5VykR7vQcRl20Dl1txZwnXSScml16mp5fAWVjxMg5bMORoNc8lhit/mUw0E
# jQba6leB7h9BDCfx7bSYfq2BfGdP4bdNQfIu7nZKV7yzjP+iehFQHQnOJguRPzrV
# AgMBAAGjggGxMIIBrTAfBgNVHSMEGDAWgBQO4TqoUzox1Yq+wbutZxoDha00DjAd
# BgNVHQ4EFgQUklhmmnHnHkti7YYbhjHWCUVZTxAwDgYDVR0PAQH/BAQDAgeAMAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEQYJYIZIAYb4QgEBBAQD
# AgQQMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0
# dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEATBDBgNVHR8EPDA6MDigNqA0
# hjJodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29SU0FDb2RlU2lnbmluZ0NB
# LmNybDBzBggrBgEFBQcBAQRnMGUwPgYIKwYBBQUHMAKGMmh0dHA6Ly9jcnQuc2Vj
# dGlnby5jb20vU2VjdGlnb1JTQUNvZGVTaWduaW5nQ0EuY3J0MCMGCCsGAQUFBzAB
# hhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAfBgNVHREEGDAWgRRzYWxlc0BrcmVz
# dGZpZWxkLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAbe/ejc5na4yymmLj2BntXz5U
# K63p/XJ/Pzy6htophko+bjOP7ZzA4o6OgIv4Gtw83usduQJ4EYulXwPGD+fJwUCE
# DjoVbdmCIjzdNmKUcDtAlVB4KCByU1dfHFzAyWqFaj2zdUAwSiNz3sj/sjgFDv6A
# fzPIKvzEgI0mB/8vR63K027/PVlh2sVZk2vyw6mbhfTb9mQASq6zYQZh+tkjkdog
# Aa2gdeySl7r5rEE2TMZMmBX+9sLWT5lSVVh9wGWH6Z436ADjVtdOWh/PJ+B8R0JM
# DaCC/BocCdF9A1khSBdSTOMLXegRByb7yGlli/GbRpugnJub6rnfhb0ifdgUIDCC
# BYEwggRpoAMCAQICEDlyRDr5IrdR19NsEN0xNZUwDQYJKoZIhvcNAQEMBQAwezEL
# MAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
# BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM
# GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0xOTAzMTIwMDAwMDBaFw0yODEy
# MzEyMzU5NTlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEU
# MBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0
# d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhv
# cml0eTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIASZRc2DsPbCLPQ
# rFcNdu3NJ9NMrVCDYeKqIE0JLWQJ3M6Jn8w9qez2z8Hc8dOx1ns3KBErR9o5xrw6
# GbRfpr19naNjQrZ28qk7K5H44m/Q7BYgkAk+4uh0yRi0kdRiZNt/owbxiBhqkCI8
# vP4T8IcUe/bkH47U5FHGEWdGCFHLhhRUP7wz/n5snP8WnRi9UY41pqdmyHJn2yFm
# sdSbeAPAUDrozPDcvJ5M/q8FljUfV1q3/875PbcstvZU3cjnEjpNrkyKt1yatLcg
# Pcp/IjSufjtoZgFE5wFORlObM2D3lL5TN5BzQ/Myw1Pv26r+dE5px2uMYJPexMcM
# 3+EyrsyTO1F4lWeL7j1W/gzQaQ8bD/MlJmszbfduR/pzQ+V+DqVmsSl8MoRjVYnE
# DcGTVDAZE6zTfTen6106bDVc20HXEtqpSQvf2ICKCZNijrVmzyWIzYS4sT+kOQ/Z
# Ap7rEkyVfPNrBaleFoPMuGfi6BOdzFuC00yz7Vv/3uVzrCM7LQC/NVV0CUnYSVga
# f5I25lGSDvMmfRxNF7zJ7EMm0L9BX0CpRET0medXh55QH1dUqD79dGMvsVBlCeZY
# Qi5DGky08CVHWfoEHpPUJkZKUIGy3r54t/xnFeHJV4QeD2PW6WK61l9VLupcxigI
# BCU5uA4rqfJMlxwHPw1S9e3vL4IPAgMBAAGjgfIwge8wHwYDVR0jBBgwFoAUoBEK
# Iz6W8Qfs4q8p74Klf9AwpLQwHQYDVR0OBBYEFFN5v1qqK0rPVIDh2JvAnfKyA2bL
# MA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MBEGA1UdIAQKMAgwBgYE
# VR0gADBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9B
# QUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQwFAAOC
# AQEAGIdR3HQhPZyK4Ce3M9AuzOzw5steEd4ib5t1jp5y/uTW/qofnJYt7wNKfq70
# jW9yPEM7wD/ruN9cqqnGrvL82O6je0P2hjZ8FODN9Pc//t64tIrwkZb+/UNkfv3M
# 0gGhfX34GRnJQisTv1iLuqSiZgR2iJFODIkUzqJNyTKzuugUGrxx8VvwQQuYAAoi
# AxDlDLH5zZI3Ge078eQ6tvlFEyZ1r7uq7z97dzvSxAKRPRkA0xdcOds/exgNRc2T
# hZYvXd9ZFk8/Ub3VRRg/7UqO6AZhdCMWtQ1QcydER38QXYkqa4UxFMToqWpMgLxq
# eM+4f452cpkMnf7XkQgWoaNflTCCBfUwggPdoAMCAQICEB2iSDBvmyYY0ILgln0z
# 02owDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcg
# SmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJU
# UlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRp
# b24gQXV0aG9yaXR5MB4XDTE4MTEwMjAwMDAwMFoXDTMwMTIzMTIzNTk1OVowfDEL
# MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
# BxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSQwIgYDVQQDExtT
# ZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQCGIo0yhXoYn0nwli9jCB4t3HyfFM/jJrYlZilAhlRGdDFixRDt
# socnppnLlTDAVvWkdcapDlBipVGREGrgS2Ku/fD4GKyn/+4uMyD6DBmJqGx7rQDD
# YaHcaWVtH24nlteXUYam9CflfGqLlR5bYNV+1xaSnAAvaPeX7Wpyvjg7Y96Pv25M
# QV0SIAhZ6DnNj9LWzwa0VwW2TqE+V2sfmLzEYtYbC43HZhtKn52BxHJAteJf7wtF
# /6POF6YtVbC3sLxUap28jVZTxvC6eVBJLPcDuf4vZTXyIuosB69G2flGHNyMfHEo
# 8/6nxhTdVZFuihEN3wYklX0Pp6F8OtqGNWHTAgMBAAGjggFkMIIBYDAfBgNVHSME
# GDAWgBRTeb9aqitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQUDuE6qFM6MdWKvsG7
# rWcaA4WtNA4wDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0lBBYwFAYIKwYBBQUHAwMGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQ
# BgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRy
# dXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEEajBo
# MD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0
# UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0
# cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAE1jUO1HNEphpNveaiqMm/EAAB4d
# Yns61zLC9rPgY7P7YQCImhttEAcET7646ol4IusPRuzzRl5ARokS9At3WpwqQTr8
# 1vTr5/cVlTPDoYMot94v5JT3hTODLUpASL+awk9KsY8k9LOBN9O3ZLCmI2pZaFJC
# X/8E6+F0ZXkI9amT3mtxQJmWunjxucjiwwgWsatjWsgVgG10Xkp1fqW4w2y1z99K
# eYdcx0BNYzX2MNPPtQoOCwR/oEuuu6Ol0IQAkz5TXTSlADVpbL6fICUQDRn7UJBh
# vjmPeo5N9p8OHv4HURJmgyYZSJXOSsnBf/M6BZv5b9+If8AjntIeQ3pFMcGcTanw
# WbJZGehqjSkEAnd8S0vNcL46slVaeD68u28DECV3FTSK+TbMQ5Lkuk/xYpMoJVcp
# +1EZx6ElQGqEV8aynbG8HArafGd+fS7pKEwYfsR7MUFxmksp7As9V1DSyt39ngVR
# 5UR43QHesXWYDVQk/fBO4+L4g71yuss9Ou7wXheSaG3IYfmm8SoKC6W59J7umDIF
# hZ7r+YMp08Ysfb06dy6LN0KgaoLtO0qqlBCk4Q34F8W2WnkzGJLjtXX4oemOCiUe
# 5B7xn1qHI/+fpFGe+zmAEc3btcSnqIBv5VPU4OOiwtJbGvoyJi1qV3AcPKRYLqPz
# W0sH3DJZ84enGm1YMIIG7DCCBNSgAwIBAgIQMA9vrN1mmHR8qUY2p3gtuTANBgkq
# hkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkx
# FDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5l
# dHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRo
# b3JpdHkwHhcNMTkwNTAyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjB9MQswCQYDVQQG
# EwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxm
# b3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28g
# UlNBIFRpbWUgU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDIGwGv2Sx+iJl9AZg/IJC9nIAhVJO5z6A+U++zWsB21hoEpc5Hg7XrxMxJ
# NMvzRWW5+adkFiYJ+9UyUnkuyWPCE5u2hj8BBZJmbyGr1XEQeYf0RirNxFrJ29dd
# SU1yVg/cyeNTmDoqHvzOWEnTv/M5u7mkI0Ks0BXDf56iXNc48RaycNOjxN+zxXKs
# Lgp3/A2UUrf8H5VzJD0BKLwPDU+zkQGObp0ndVXRFzs0IXuXAZSvf4DP0REKV4TJ
# f1bgvUacgr6Unb+0ILBgfrhN9Q0/29DqhYyKVnHRLZRMyIw80xSinL0m/9NTIMdg
# aZtYClT0Bef9Maz5yIUXx7gpGaQpL0bj3duRX58/Nj4OMGcrRrc1r5a+2kxgzKi7
# nw0U1BjEMJh0giHPYla1IXMSHv2qyghYh3ekFesZVf/QOVQtJu5FGjpvzdeE8Nfw
# KMVPZIMC1Pvi3vG8Aij0bdonigbSlofe6GsO8Ft96XZpkyAcSpcsdxkrk5WYnJee
# 647BeFbGRCXfBhKaBi2fA179g6JTZ8qx+o2hZMmIklnLqEbAyfKm/31X2xJ2+opB
# JNQb/HKlFKLUrUMcpEmLQTkUAx4p+hulIq6lw02C0I3aa7fb9xhAV3PwcaP7Sn1F
# NsH3jYL6uckNU4B9+rY5WDLvbxhQiddPnTO9GrWdod6VQXqngwIDAQABo4IBWjCC
# AVYwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFBqh
# +GEZIA/DQXdFKI7RNV8GEgRVMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAG
# AQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQ
# BgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRy
# dXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEEajBo
# MD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0
# UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0
# cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAG1UgaUzXRbhtVOBkXXfA3oyCy0l
# hBGysNsqfSoF9bw7J/RaoLlJWZApbGHLtVDb4n35nwDvQMOt0+LkVvlYQc/xQuUQ
# ff+wdB+PxlwJ+TNe6qAcJlhc87QRD9XVw+K81Vh4v0h24URnbY+wQxAPjeT5OGK/
# EwHFhaNMxcyyUzCVpNb0llYIuM1cfwGWvnJSajtCN3wWeDmTk5SbsdyybUFtZ83J
# b5A9f0VywRsj1sJVhGbks8VmBvbz1kteraMrQoohkv6ob1olcGKBc2NeoLvY3NdK
# 0z2vgwY4Eh0khy3k/ALWPncEvAQ2ted3y5wujSMYuaPCRx3wXdahc1cFaJqnyTdl
# Hb7qvNhCg0MFpYumCf/RoZSmTqo9CfUFbLfSZFrYKiLCS53xOV5M3kg9mzSWmglf
# jv33sVKRzj+J9hyhtal1H3G/W0NdZT1QgW6r8NDT/LKzH7aZlib0PHmLXGTMze4n
# muWgwAxyh8FuTVrTHurwROYybxzrF06Uw3hlIDsPQaof6aFBnf6xuKBlKjTg3qj5
# PObBMLvAoGMs/FwWAKjQxH/qEZ0eBsambTJdtDgJK0kHqv3sMNrxpy/Pt/360KOE
# 2See+wFmd7lWEOEgbsausfm2usg1XTN2jvF8IAwqd661ogKGuinutFoAsYyr4/kK
# yVRd1LlqdJ69SK6YMIIG9jCCBN6gAwIBAgIRAJA5f5rSSjoT8r2RXwg4qUMwDQYJ
# KoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFu
# Y2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1p
# dGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBMB4XDTIy
# MDUxMTAwMDAwMFoXDTMzMDgxMDIzNTk1OVowajELMAkGA1UEBhMCR0IxEzARBgNV
# BAgTCk1hbmNoZXN0ZXIxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UE
# AwwjU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBTaWduZXIgIzMwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQCQsnE/eeHUuYoXzMOXwpCUcu1aOm8BQ39z
# WiifJHygNUAG+pSvCqGDthPkSxUGXmqKIDRxe7slrT9bCqQfL2x9LmFR0IxZNz6m
# XfEeXYC22B9g480Saogfxv4Yy5NDVnrHzgPWAGQoViKxSxnS8JbJRB85XZywlu1a
# SY1+cuRDa3/JoD9sSq3VAE+9CriDxb2YLAd2AXBF3sPwQmnq/ybMA0QfFijhanS2
# nEX6tjrOlNEfvYxlqv38wzzoDZw4ZtX8fR6bWYyRWkJXVVAWDUt0cu6gKjH8JgI0
# +WQbWf3jOtTouEEpdAE/DeATdysRPPs9zdDn4ZdbVfcqA23VzWLazpwe/OpwfeZ9
# S2jOWilh06BcJbOlJ2ijWP31LWvKX2THaygM2qx4Qd6S7w/F7KvfLW8aVFFsM7ON
# WWDn3+gXIqN5QWLP/Hvzktqu4DxPD1rMbt8fvCKvtzgQmjSnC//+HV6k8+4WOCs/
# rHaUQZ1kHfqA/QDh/vg61MNeu2lNcpnl8TItUfphrU3qJo5t/KlImD7yRg1psbdu
# 9AXbQQXGGMBQ5Pit/qxjYUeRvEa1RlNsxfThhieThDlsdeAdDHpZiy7L9GQsQkf0
# VFiFN+XHaafSJYuWv8at4L2xN/cf30J7qusc6es9Wt340pDVSZo6HYMaV38cAcLO
# HH3M+5YVxQIDAQABo4IBgjCCAX4wHwYDVR0jBBgwFoAUGqH4YRkgD8NBd0UojtE1
# XwYSBFUwHQYDVR0OBBYEFCUuaDxrmiskFKkfot8mOs8UpvHgMA4GA1UdDwEB/wQE
# AwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMEoGA1Ud
# IARDMEEwNQYMKwYBBAGyMQECAQMIMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2Vj
# dGlnby5jb20vQ1BTMAgGBmeBDAEEAjBEBgNVHR8EPTA7MDmgN6A1hjNodHRwOi8v
# Y3JsLnNlY3RpZ28uY29tL1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcmwwdAYI
# KwYBBQUHAQEEaDBmMD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnNlY3RpZ28uY29t
# L1NlY3RpZ29SU0FUaW1lU3RhbXBpbmdDQS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6
# Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4ICAQBz2u1ocsvCuUCh
# Mbu0A6MtFHsk57RbFX2o6f2t0ZINfD02oGnZ85ow2qxp1nRXJD9+DzzZ9cN5JWwm
# 6I1ok87xd4k5f6gEBdo0wxTqnwhUq//EfpZsK9OU67Rs4EVNLLL3OztatcH714l1
# bZhycvb3Byjz07LQ6xm+FSx4781FoADk+AR2u1fFkL53VJB0ngtPTcSqE4+XrwE1
# K8ubEXjp8vmJBDxO44ISYuu0RAx1QcIPNLiIncgi8RNq2xgvbnitxAW06IQIkwf5
# fYP+aJg05Hflsc6MlGzbA20oBUd+my7wZPvbpAMxEHwa+zwZgNELcLlVX0e+OWTO
# t9ojVDLjRrIy2NIphskVXYCVrwL7tNEunTh8NeAPHO0bR0icImpVgtnyughlA+Xx
# KfNIigkBTKZ58qK2GpmU65co4b59G6F87VaApvQiM5DkhFP8KvrAp5eo6rWNes7k
# 4EuhM6sLdqDVaRa3jma/X/ofxKh/p6FIFJENgvy9TZntyeZsNv53Q5m4aS18YS/t
# o7BJ/lu+aSSR/5P8V2mSS9kFP22GctOi0MBk0jpCwRoD+9DtmiG4P6+mslFU1UzF
# yh8SjVfGOe1c/+yfJnatZGZn6Kow4NKtt32xakEnbgOKo3TgigmCbr/j9re8ngsp
# GGiBoZw/bhZZSxQJCZrmrr9gFd2G9TGCBYMwggV/AgEBMIGRMHwxCzAJBgNVBAYT
# AkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZv
# cmQxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEkMCIGA1UEAxMbU2VjdGlnbyBS
# U0EgQ29kZSBTaWduaW5nIENBAhEAzbmP/0u+zbSX3lLqrOK9+TAJBgUrDgMCGgUA
# oHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYB
# BAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0B
# CQQxFgQUXW+/kweLMh9j9+mZCQKcBOLyUrEwDQYJKoZIhvcNAQEBBQAEggEAUhan
# jzHDcWnQyraTDMXqGdUikDQjqBdXuw220R/5bnNeXGb39o4KMDE88hvHlxK1gBCI
# cNLxbuzmr7O7kzgUMiYkTXChG+GT6fXtisHL9MV3maeefAWZTuVGyyM6F2XzfLc8
# rVdofwp7gEiUwM7h0jpumt7PQeFSiZxVVeRgO2ewvbc7MVgnoJOwyY6tSTPkHRrM
# PyZmwT2BLStKBhk7DiybqAh3PzIn2V7eKnEBGLRogG8yCYjmBFqOwjQK7c0XCo+1
# aHG3MY0PkKZmKvf80G1/bGuHVikY+yD47UBosccHD481AVni+sWn7dMC2cDnx3xw
# JB7yoHlpO1WR0hoFsKGCA0wwggNIBgkqhkiG9w0BCQYxggM5MIIDNQIBATCBkjB9
# MQswCQYDVQQGEwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
# VQQHEwdTYWxmb3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMT
# HFNlY3RpZ28gUlNBIFRpbWUgU3RhbXBpbmcgQ0ECEQCQOX+a0ko6E/K9kV8IOKlD
# MA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkq
# hkiG9w0BCQUxDxcNMjMwMjIzMTYwNTI1WjA/BgkqhkiG9w0BCQQxMgQwHAbPDU8n
# MpGWCQ7WP8uKHz5VE1GB2anL6wbYHnUopQDBo95gRabre5VUW0Qt+bRPMA0GCSqG
# SIb3DQEBAQUABIICAInZn+aoMJjWfGjnS9kYrWcvsuw5yOzbifg7EgYBhcYOWvK4
# 06GkciYvQ1RYKSYwUJ/Q5Nz6Idm7tgens45WiUpztwm/lePBXHnRlL9QACnaleMb
# wIUTf8kXTE+dcvhIX2tNMtuYNUfmu+Z2VQYaAFL0bpLwiJGDQUtrap+YJe17q9zU
# kYF0ABlNUy7djwoaR3iCJpDSJsEPmF3zZwHJYfKwaY6RL0rkZ+bYtGBqMWPrMZS8
# G1AMadazkawv8h9GNUImfNoLPOmNM1AFZcIpPWgPKHWCDbsQBXjV/m2H0MRzQ7Uf
# nG5oApqKgtVQ5psoUMCNA03BGhAdUlpNONivmJf9I0+Qskoucpc1BW3YsflATWR7
# oNJp92iV/JobX0l7MPTMRKBU3yIME8QVtEEDCxOK+CFBbVAQ39bCKq6a69uWkjU/
# R6yx8trgSexxnWk6FLiLij0QKJUx0BcRx/dSYT5kqZGU+Oaf1RCf5jCAgoCxnbOq
# dzcJu3IeHJHkFphrUvmK4oIfscqwzjACEQTduQVOHI1nx25VKsKqD6vSQWGF0uou
# Nr0++b7AoLhNc6nnpcVa4AxKSfDJPEIPNRh01H2y6vQ/8ZBx8JzifOG8QtFQpTu6
# Mfa5IQp6+tJM22dFUBmCjH7VhnT4xJDq1/fljSDUSrhJ/H9Y67wOWHqc6wcP
# SIG # End signature block
