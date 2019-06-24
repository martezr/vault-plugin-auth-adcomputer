1. Get computername
2. Get guid
3. Authenticate against vault using the computername and guid
4. Request an SSL certificate using the returned token
5. Add the SSL certificate to the local keystore
6. Configure WinRM w/SSL using the new SSL certificate

$computername
$guid =
