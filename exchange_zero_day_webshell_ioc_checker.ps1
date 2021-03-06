# PowerShell Web Shell IOC Checker for Microsoft Exchange Zero-day Exploits, March 2021
# Based on IOCs published by Microsoft: https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/ 
# Written by Justin Wilson
# Version 1.0 
# Date: 5 March 2021

# This script will check for the existence of web shells which have been found on compromised systems
# as a result of the March 2021 Microsoft Exchange Zero-day Exploits

# Define web shell filenames
$webshells = @(
    "web.aspx", 
    "help.aspx", 
    "document.aspx", 
    "errorEE.aspx", 
    "errorEEE.aspx", 
    "errorEW.aspx", 
    "errorFF.aspx", 
    "healthcheck.aspx", 
    "aspnet_www.aspx", 
    "aspnet_client.aspx", 
    "xx.aspx", 
    "shell.aspx", 
    "aspnet_iisstart.aspx", 
    "one.aspx"
    )

# Define web shell SHA256 hashes
$webshellHashes = @(
    "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0",
    "097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e",
    "2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1",
    "65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5",
    "511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1",
    "4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea",
    "811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d",
    "1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944"
)
# Dummy hash to use for testing (blank file): "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

# Define web shell paths
$path = @(
    "C:\inetpub\wwwroot\aspnet_client\",
    "$Env:Programfiles\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\",
    "C:\Exchange\FrontEnd\HttpProxy\owa\auth\"
    )

# Create 'iocs' array
$IOCs = [System.Collections.ArrayList]@()

# Search for IOCs and add results to $IOCs
Get-Childitem -Path $path -Include $webshells -Recurse -ErrorAction SilentlyContinue | Get-FileHash -Algorithm SHA256 | %{ If ($webshellHashes.Contains($_.hash)) { $IOCs.Add($_) | out-null } }

# Print results
if ($IOCs.Count -gt 0) {
    write-host -ForegroundColor red "Web shell IOC(s) Detected!"
    $IOCs | select Path,Hash
} else {
    write-host -ForegroundColor green "No IOCs found."
}
