###############################################################################
# Script per la registrazione su CyberArk degli utenti da utilizzare per la 
# connesione alle VM FullManaged
# DXC Techonology for Regione Toscana
# Versione 1.0 - 11.02.2022
# Authors: 
###############################################################################
# Note di versione
# 1.0 - versione iniziale
###############################################################################

# Variabili ottenute da Morpheus
$morpheus_client="<%=morpheus.account%>"
$morpheus_ip="<%=server.internalIp%>"
$hostname="<%=server.hostname%>"
$domainName="<%=server.domainName%>"
$morpheus_cyk_api_user="<%=cypher.read('secret/cyk_api_user',true)%>"
$morpheus_cyk_api_pasw="<%=cypher.read('secret/cyk_api_password',true)%>"
$morpheus_read_secret="<%=cypher.read('secret/cyk_read_password',true)%>"
$morpheus_admin_secret="<%=cypher.read('secret/cyk_read_password',true)%>"

# Variabili Locali
$local_safe_windows="AUTOUP-Windows"
$local_platform_id_read_windows="AUTOUP-WindowsRead"
$local_platform_id_admin_windows="AUTOUP-WindowsAdmin"
$local_read_suffix="_cyk_read"
$local_admin_suffix="_cyk_admin"
$local_secret_type="password"
$local_comment="Utente CyberArk"
$local_os="Windows"
$local_fqdn=$hostname+"."+$domainName

# URL API CyberArk
$local_cyk_api_url="https://pam.rt.sistemacloudtoscana.it/PasswordVault/API"
$local_cyk_api_url_logon=$local_cyk_api_url + "/auth/Cyberark/Logon"
$local_cyk_api_url_account=$local_cyk_api_url + "/Accounts"
$local_cyk_api_url_logoff=$local_cyk_api_url + "/Auth/Logoff"
$local_token_cyb_logon =""

function BypassSSLCheck {
    # Bypass SSL Check for Invoke-RestMethod
    # N.B. Il parametro -SkipCertificateCheck del comando Invoke-RestMethod non è disponibile nella versione 5.1 di PowerShell
    #      installata di default su Windowso 2019
    try {
        add-type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(
                    ServicePoint srvPoint, X509Certificate certificate,
                    WebRequest request, int certificateProblem) {
                    return true;
                }
            } 
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
    catch
        {
        Write-Warning -Message "Errore nell'impostazione del Check sul Certificato: "
		Write-Warning $Error[0].ToString()
        }
}

function LogonToCyberArk {
    param (
        [string]$morpheus_cyk_api_user,
        [string]$morpheus_cyk_api_pasw,
        [string]$local_cyk_api_url_logon
    )

    #Request body
    $Body = @{
        username = $morpheus_cyk_api_user
        password = $morpheus_cyk_api_pasw
    }
    $JsonBody = $Body | ConvertTo-Json

    #send request to web service
    $Params = @{
        Method = "Post"
        Uri = $local_cyk_api_url_logon
        Body = $JsonBody
        ContentType = "application/json"
    }
    # SLO DEBUG write-host "LogonToCyberArk: $JsonBody"
    try { $local_token_cyb_logon = (Invoke-RestMethod @Params) } catch { Write-Host "Errore acquisizione token su $local_cyk_api_url_logon`nCodice: $_`nVerificare con il supporto"; exit 1 } 
    return $local_token_cyb_logon
}

function AddUserToCyberArk {
    param (
        [string]$local_token_cyb_logon,
        [string]$local_cyk_api_url_account,
        [string]$local_safe_windows,
        [string]$morpheus_client,
        [string]$morpheus_ip,
        [string]$local_fqdn,
        [string]$local_platform_id_read_windows,
        [string]$local_platform_id_admin_windows,
        [string]$local_read_suffix,
        [string]$morpheus_read_secret,
        [string]$local_admin_suffix,
        [string]$morpheus_admin_secret,
        [string]$local_secret_type,
        [string]$local_os
    )

    #Request body
    $Body = @{
        name = $morpheus_client+$local_read_suffix+"@"+$morpheus_ip+"@"+$local_os
        address=$local_fqdn
        userName=$morpheus_client+$local_read_suffix
        platformId=$local_platform_id_read_windows
        safeName=$local_safe_windows
        secretType=$local_secret_type
        secret=$morpheus_read_secret
        platformAccountProperties=@{IPAddress=$morpheus_ip}
    }
    $JsonBody = $Body | ConvertTo-Json

    #send request to web service
    $Params = @{
        Method = "Post"
        Uri = $local_cyk_api_url_account
        Body = $JsonBody
        ContentType = "application/json"
    }
    $headers = @{
        'Authorization' = $local_token_cyb_logon
    }
    # SLO DEBUG write-host "DEBUG - AddUserToCyberArk: $JsonBody"
    try { Invoke-RestMethod -Headers $headers @Params } catch { Write-Host "Errore nella definizione dell'utenza $morpheus_client$local_read_suffix@$morpheus_ip@$local_os su CyberArk`nCodice: $_`nVerificare con il supporto"; exit 1 } 

    $Body = @{
        name = $morpheus_client+$local_admin_suffix+"@"+$morpheus_ip+"@"+$local_os
        address=$local_fqdn
        userName=$morpheus_client+$local_admin_suffix
        platformId=$local_platform_id_admin_windows
        safeName=$local_safe_windows
        secretType=$local_secret_type
        secret=$morpheus_admin_secret
        platformAccountProperties=@{IPAddress=$morpheus_ip}
    }
    $JsonBody = $Body | ConvertTo-Json

    #send request to web service
    $Params = @{
        Method = "Post"
        Uri = $local_cyk_api_url_account
        Body = $JsonBody
        ContentType = "application/json"
    }
    $headers = @{
        'Authorization' = $local_token_cyb_logon
    }
    # SLO DEBUG write-host "DEBUG - AddUserToCyberArk: $JsonBody"
    try { Invoke-RestMethod -Headers $headers @Params } catch { Write-Host "Errore nella definizione dell'utenza  $morpheus_client$local_admin_suffix@$morpheus_ip@$local_os su CyberArk`nCodice: $_`nVerificare con il supporto"; exit 1} 
}

function LogoffFromCyberArk {
    param (
        [string]$local_token_cyb_logon,
        [string]$local_cyk_api_url_logoff
    )

    #send request to web service
    $Params = @{
        Method = "Post"
        Uri = $local_cyk_api_url_logoff
        ContentType = "application/json"
    }
    $headers = @{
        'Authorization' = $local_token_cyb_logon
    }
    # SLO DEBUG write-host "LogoffFromCyberArk: $JsonBody"
    Invoke-RestMethod -Headers $headers @Params
}

function AddUserToSO {
    param (
        [string]$local_comment,
        [string]$morpheus_client,
        [string]$local_read_suffix,
        [string]$morpheus_read_secret,
        [string]$local_admin_suffix,
        [string]$morpheus_admin_secret
    )

    $userName=$morpheus_client+$local_read_suffix
    $secureString = convertto-securestring $morpheus_read_secret -asplaintext -force
    # SLO DEBUG write-host "AddUserToSO: $userName"
    # SLO DEBUG write-host "AddUserToSO: $morpheus_read_secret"
    # SLO DEBUG write-host "AddUserToSO: $local_comment"
    New-LocalUser $userName -Password $secureString -Description $local_comment
    Add-LocalGroupMember -Group 'Remote Desktop Users' -Member ($userName)
    Add-LocalGroupMember -Group 'Users' -Member ($userName)

    $userName=$morpheus_client+$local_admin_suffix
    $secureString = convertto-securestring $morpheus_admin_secret -asplaintext -force
    # SLO DEBUG write-host "AddUserToSO: $userName"
    # SLO DEBUG write-host "AddUserToSO: $morpheus_admin_secret"
    New-LocalUser $userName -Password $secureString -Description $local_comment
    Add-LocalGroupMember -Group 'Administrators' -Member ($userName)
}

# Main

# Aggiungo entry in file hosts
# Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`n10.159.250.38`tpam.rt.sistemacloudtoscana.it" -Force

#Disabilito il controllo sui certificati
BypassSSLCheck

#Effettuo il logon a CybrArk
$local_token_cyb_logon = LogonToCyberArk $morpheus_cyk_api_user $morpheus_cyk_api_pasw $local_cyk_api_url_logon

#Aggiungo gli utenti a CyberArk
AddUserToCyberArk $local_token_cyb_logon $local_cyk_api_url_account `
                  $local_safe_windows $morpheus_client $morpheus_ip $local_fqdn `
                  $local_platform_id_read_windows $local_platform_id_admin_windows `
                  $local_read_suffix $morpheus_read_secret `
                  $local_admin_suffix $morpheus_admin_secret `
                  $local_secret_type $local_os

#Effettuo il logoff da CybrArk
LogoffFromCyberArk $local_token_cyb_logon $local_cyk_api_url_logoff

#Aggiungo gli utenti Windows
AddUserToSO $local_comment $morpheus_client `
            $local_read_suffix $morpheus_read_secret `
            $local_admin_suffix $morpheus_admin_secret
