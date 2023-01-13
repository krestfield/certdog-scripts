# Automated Setup

A simple script to download, install and configure a test instance of certdog  



This script will perform the following:

* Download certdog

* Install the VC++ requirements

* Install certdog

It will then configure the following:

* A root CA with CRL configured

* An issuing CA with CRL and OCSP services configured
* A TLS certificate profile
* A CSR generator
* A Certificate Issuer - consisting of the Issuing CA and TLS profile

The default certdog test root, the Root CA and Issuing CA certificates will be installed to the local machine store



## To Run

Download the script and edit this section:

```powershell
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
```

Setting the values as required. Note that ``adminUsername`` and ``adminPassword`` are the credentials you will use to first login  

Adjust the CA names and DNs as required but all values can be left at their defaults for testing purposes



Open a PowerShell script as Administrator, navigate to where you downloaded the script, e.g.:

```
c:\tmp
```

And run the script:

```
.\automated-setup.ps1
```



On completion, login to certdog from this URL:

https://127.0.0.1/certdog

Navigate to **Request**, then **DN Request**. Enter the **Subject DN** and a **P12 Password** and click **Request Certificate**

Download the P12 or certificate. It will be trusted on the local machine  



