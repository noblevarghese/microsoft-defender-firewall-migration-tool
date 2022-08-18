. "$PSScriptRoot\ConvertTo-IntuneFirewallRule.ps1"
. "$PSScriptRoot\Get-SampleFirewallData.ps1"
. "$PSScriptRoot\..\Private\Strings.ps1"

function Export-NetFirewallRule {
    <#
    .SYNOPSIS
    Exports network firewall rules found on this host into Intune firewall rules.

    .DESCRIPTION
    Export-NetFirewallRule will export all network firewall rules found on the host and convert them into an
    intermediate IntuneFirewallRule object

    .EXAMPLE
    Export-NetFirewallRule
    Export-NetFirewallRule -PolicyStoreSource GroupPolicy
    Export-NetFirewallRule -PolicyStoreSource All
    Export-NetFirewallRule -splitConflictingAttributes -sendExportTelemetry

    .NOTES
    Export-NetFirewallRule is a wrapper for the cmdlet call to Get-NetFirewallRule piped to ConvertTo-IntuneFirewallRule.

    If -splitConflictingAttributes is toggled, then firewall rules with multiple attributes of filePath, serviceName,
    or packageFamilyName will automatically be processed and split instead of prompting users to split the firewall rule

    If -sendExportTelemetry is toggled, then error messages encountered will automatically be sent to Microsoft and the
    tool will continue processing net firewall rules.

    .LINK
    https://docs.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=win10-ps#description

    .OUTPUTS
    IntuneFirewallRule[]

    A stream of exported firewall rules represented via the intermediate IntuneFirewallRule class
    #>
    [CmdletBinding()]
    Param(
         #Defines the profile Name for the set of rules to be imported
         [Parameter(Mandatory = $true)]
         [String]
         $ProfileName,
        # Defines the policy store source to pull net firewall rules from.
        [ValidateSet("GroupPolicy", "All")]
        [string] $PolicyStoreSource = "GroupPolicy",
        # If this switch is toggled, only the firewall rules that are currently enabled are imported 
        [boolean]
        $EnabledOnly =$True,
        # This determines if we are running a test version or a full importation. The default value is full. The test version imports only 20 rules
        [ValidateSet("Full","Test")]
        [String]
        $Mode = "Full",
        [bool]
        $CheckProfileName = $true,
        # If this flag is toggled, then firewall rules with multiple attributes of filePath, serviceName,
        # or packageFamilyName will not automatically be processed and split and the users will be prompted users to split
        [switch] $doNotsplitConflictingAttributes,
        # If this flag is toggled, then telemetry is automatically sent to Microsoft.
        [switch] $sendExportTelemetry,
        # If this flag is toogled, then firewall rules would be imported to Device Configuration else it would be import to Endpoint Security
        [Switch]
        $DeviceConfiguration
        

         
    )
        if($CheckProfileName -eq $true)
        {
            
            try
            {
                $json = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/Configurationpolicies" -Headers $global:authHeader
                $profiles = $json.value
                $profileNameExist = $true
                while($profileNameExist)
                {
                    
                    foreach($display in $profiles)
                    {
                        $name = $display.name.Split("-")
                        $profileNameExist = $false
                        if($name[0] -eq $ProfileName)
                        {
                            $profileNameExist = $true
                            $profileName = Read-Host -Prompt $Strings.ProfileExists
                            while(-not($profileName))
                            {
                                $profileName = Read-Host -Prompt  $Strings.ProfileCannotBeBlank  
                            }
                            break
                        }
                    }
                }
            }
            catch{
                $errorMessage = $_.ToString()
            
                Write-Error $errorMessage
                return
            }

        }

        $choice = 1

        Switch ($choice) {
            0{$sendExportTelemetry = $True}
            1{$sendExportTelemetry = $False}
        }

        
            # The default behavior for Get-NetFirewallRule is to retrieve all WDFWAS firewall rules
        return $(Get-FirewallData -Enabled:$EnabledOnly -Mode:$Mode -PolicyStoreSource:$PolicyStoreSource| ConvertTo-IntuneFirewallRule `
                -doNotsplitConflictingAttributes:$doNotsplitConflictingAttributes `
                -sendConvertTelemetry:$sendExportTelemetry `
                -DeviceConfiguration:$DeviceConfiguration `
                | Send-IntuneFirewallRulesPolicy `
                -migratedProfileName:$ProfileName `
                -sendIntuneFirewallTelemetry:$sendExportTelemetry `
                -DeviceConfiguration:$DeviceConfiguration
                )
        
}