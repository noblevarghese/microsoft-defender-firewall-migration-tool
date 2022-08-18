
param([switch]$includeDisabledRules, [switch]$includeLocalRules)
  
## check for elevation   
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
  
if (!$principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host -ForegroundColor Red "Error:  Must run elevated: run as administrator"
    Write-Host "No commands completed"
    return
}

#----------------------------------------------------------------------------------------------C:\Users\t-oktess\Documents\powershellproject
if (-not(Test-Path ".\defender-firewall-migration.zip")) {
    #Download a zip file which has other required files from the public repo on github
    Invoke-WebRequest -Uri "https://github.com/noblevarghese/microsoft-defender-firewall-migration-tool/archive/main.zip" -OutFile ".\defender-firewall-migration.zip"

    #Unblock the files especially since they are download from the internet
    Get-ChildItem ".\defender-firewall-migration.zip" -Recurse -Force | Unblock-File

    #Unzip the files into the current direectory
    Expand-Archive -LiteralPath ".\defender-firewall-migration.zip" -DestinationPath ".\" -Force
}
#----------------------------------------------------------------------------------------------

#Import all the right modules
Import-Module ".\microsoft-defender-firewall-migration-tool-main\Modules\IntuneFirewallRulesMigration\FirewallRulesMigration.psm1" -Force
. ".\microsoft-defender-firewall-migration-tool-main\Modules\IntuneFirewallRulesMigration\IntuneFirewallRulesMigration\Private\Strings.ps1"

##Validate the user's profile name
$profileName = ""
try {
    $json = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/Configurationpolicies" -Headers $global:authHeader
    $profiles = $json.value
    $profileName = Read-Host -Prompt $Strings.EnterProfile
    while (-not($profileName)) {
        $profileName = Read-Host -Prompt $Strings.ProfileCannotBeBlank
    }

    if ($profileName -in $profiles.name) {
        $profileName = Read-Host -Prompt $Strings.ProfileExists
        while (-not($profileName)) {
            $profileName = Read-Host -Prompt $Strings.ProfileCannotBeBlank 
        }
    }

    $EnabledOnly = $true
    if ($includeDisabledRules) {
        $EnabledOnly = $false
    }

    if ($includeLocalRules) {
        Export-NetFirewallRule -ProfileName $profileName  -CheckProfileName $false -EnabledOnly:$EnabledOnly -PolicyStoreSource "All"
    }
    else {
        Export-NetFirewallRule -ProfileName $profileName -CheckProfileName $false -EnabledOnly:$EnabledOnly
    }
    
}
catch {
    $errorMessage = $_.ToString()
    Write-Host -ForegroundColor Red $errorMessage
    Write-Host "No commands completed"
}

    
                           
