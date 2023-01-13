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

# Download the installer
Write-Host "`nDownloading certdog..."
$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile('https://krestfield.s3.eu-west-2.amazonaws.com/certdog/certdogfree_v180.zip', 'c:\certdog.zip')

# Extract the zip
cd \
Expand-Archive .\certdog.zip -DestinationPath .

# Install - first install the Visual C++ requirement, then certdog using the parameters from above
cd certdogfree\install
.\VC_redist.x64.exe /install /quiet | Out-Null
.\install.ps1 -acceptEula -dbAdminPassword $dbPassword -firstAdminUsername $adminUsername -firstAdminEmail $adminEmail -firstAdminPassword $adminPassword -listeningIpAddress 0.0.0.0 -listeningPort 443 -installAdcsAgent

# Install the test root certificate to avoid local SSL errors
# NOTE: This should be removed from the local trust store once a new SSL cert has been installed
Import-Certificate -FilePath "C:\certdogfree\config\sslcerts\dbssl_root.cer" -CertStoreLocation Cert:\LocalMachine\Root

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
Set-Content -Path "c:\certdogfree\bin\rootCert.cer" -Value $cert

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
Set-Content -Path "c:\certdogfree\bin\intCert.cer" -Value $intCert

$ocspServer = Set-OCSPForLocalCA -id $intCa.id

# Create the TLS cert profile
$tlsProfileName = "TLS Profile"
$tlsProfile = Add-LocalCACertProfile -name $tlsProfileName -lifetimeInMinutes 129600 -includeSansFromCsr $true -enhancedKeyUsages @('clientAuth', 'serverAuth') -keyUsages @('digitalSignature','keyEncipherment')

# Create TLS cert issuer
$certIssuerName = "Certdog TLS Issuer"
$tlsCertIssuer = Add-LocalCA -caName $certIssuerName -localCaConfigId $intCa.id -certProfileId $tlsProfile.id

# Create a CSR Generator
$csrGenerator = Add-CsrGenerator -name "RSA2048 Generator" -signatureAlgorithm RSA -keySize 2048 -hashAlgorithm SHA256

# Add to Admin Team as authorised CAs
$team = team -name "Admin Team"
$updatedTeam = Update-Team -id $team.id -authorisedCas @($codeSignCertIssuer.id, $tlsCertIssuer.id)

logout

# Remove the module and call the native Import-Certificate to import the CA certs to the machine store
Remove-Module -Name certdog-module
Import-Certificate -FilePath "c:\certdogfree\bin\rootCert.cer" -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath "c:\certdogfree\bin\intCert.cer" -CertStoreLocation Cert:\LocalMachine\CA

[system.Diagnostics.Process]::Start("msedge","https://127.0.0.1")