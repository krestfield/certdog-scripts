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
