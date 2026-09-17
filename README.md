# Certdog Scripts
A collection of PowerShell and other scripts to install, create CAs and automate activities in Certdog

Including:

* automated-setup
  * A script to download, install and create some initial CAs

And scripts that can be used by the Tasks or Workflows features:

* get-certs-from-adcs
  * Queries an ADCS instance for newly issued certificates and imports them into the certdog database
  * Helps keep an ADCS database synchronised with certdog when certificates are being issued via other mechanisms (such as auto-enrolment)

* check-csr-sans-in-dns
  * Checks if the SANs included in the CSR request are registered in DNS
  * This can be used as an approval step, verifying the FQDN is a valid one

* gen-weekly-report
  * Produce a periodic CSV file summarising certificates issued

* csr-folder-watcher
  * Allows the setup of a folder where CSRs can be placed 
  * Useful for requirements such as batch processing

* renew-revoke-duplicate-certs
  * Marks certificates with the same CN or DN as renewed or revoked
  * Useful, if your requirement is to only allow one certificate at a time with the same name
