# Reads values from the module manifest file
$manifestData = Import-PowerShellDataFile -Path $PSScriptRoot\Intune-prototype-WindowsMDMFirewallRulesMigrationTool.psd1

#Installing dependencies if not already installed [msal.ps] and [ImportExcel] 
#from the powershell gallery
if (-not(Get-Module ImportExcel -ListAvailable)) {
    Write-Host "Installing ImportExcel Module from Powershell Gallery..."
    try {
        Install-Module ImportExcel -Force
    }
    catch {
        Write-Host "ImportExcel Module Powershell was not installed successfully... `r`n$_"
    }
}
if (-not(Get-Module msal.ps -ListAvailable)) {
    Write-Host "Installing msal.ps from Powershell Gallery..."
    try {
        Install-Module msal.ps -Force
    }
    catch {
        Write-Host "msal.ps was not installed successfully... `r`n$_"
    }
    
}
# Ensure required modules are imported
ForEach ($module in $manifestData["RequiredModules"]) {
    If (!(Get-Module $module)) {
        # Setting to stop will cause a terminating error if the module is not installed on the system
        Import-Module $module -ErrorAction Stop -Force
    }
}

# Port all functions and classes into this module
$Public = @( Get-ChildItem -Path $PSScriptRoot\IntuneFirewallRulesMigration\Public\*.ps1 -ErrorAction SilentlyContinue -Recurse )

# Load each public function into the module
ForEach ($import in @($Public)) {
    Try {
        . $import.fullname
    }
    Catch {
        Write-Error -Message "Failed to import function $($import.fullname): $_"
    }
}




# Exports the cmdlets provided in the module manifest file, other members are not exported
# from the module
ForEach ($cmdlet in $manifestData["CmdletsToExport"]) {
    Export-ModuleMember -Function $cmdlet
}
$client_Details = Import-Csv .\client.config
if (Get-Module Microsoft.Graph.Intune -ListAvailable) {
    try {
        $token = Get-MsalToken -DeviceCode -ClientId $client_Details.client_id -TenantId $client_Details.tenant_id -RedirectUri "https://localhost"

        $global:authHeader = @{
            'Content-Type'  = 'application/json'
            'authorization' = 'Bearer ' + $token.AccessToken
        }
    }
    catch {
        $errorMessage = $_.ToString()
        Write-Host -ForegroundColor Red "Error:"$errorMessage
        return
    }
    
}