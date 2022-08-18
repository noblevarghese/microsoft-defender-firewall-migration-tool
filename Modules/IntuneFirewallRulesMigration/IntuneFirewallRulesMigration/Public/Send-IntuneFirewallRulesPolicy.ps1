. "$PSScriptRoot\IntuneFirewallRule.ps1"
#. "$PSScriptRoot\..\Private\Send-Telemetry.ps1"
. "$PSScriptRoot\..\Private\Use-HelperFunctions.ps1"
. "$PSScriptRoot\..\Private\Strings.ps1"

$ProfileFirewallRuleLimit = 50
# Sends Intune Firewall objects out to the Intune Powershell SDK
# and returns the response to the API call

Function Send-IntuneFirewallRulesPolicy {
    <#
    .SYNOPSIS
    Send firewall rule objects out to Intune

    .DESCRIPTION
    Sends IntuneFirewallRule objects out to the Intune Powershell SDK and returns the response to the API call

    .EXAMPLE
    Get-NetFirewallRule | ConvertTo-IntuneFirewallRule | Send-IntuneFirewallRulesPolicy
    Send-IntuneFirewallRulesPolicy -firewallObjects $randomObjects
    Get-NetFirewallRule -PolicyStore RSOP | ConvertTo-IntuneFirewallRule -splitConflictingAttributes | Send-IntuneFirewallRulesPolicy -migratedProfileName "someCustomName"
    Get-NetFirewallRule -PolicyStore PersistentStore -PolicyStoreSourceType Local | ConvertTo-IntuneFirewallRule -sendConvertTelemetry | Send-IntuneFirewallRulesPolicy -migratedProfileName "someCustomName" -sendIntuneFirewallTelemetry $true

    .PARAMETER firewallObjects the collection of firewall objects to be sent to be processed
    .PARAMETER migratedProfileName an optional argument that represents the prefix for the name of newly created firewall rule profiles

    .NOTES
    While Send-IntuneFirewallRulesPolicy primarily accepts IntuneFirewallRule objects, any object piped into the cmdlet that can be
    called with the ConvertTo-Json cmdlet and represented as a JSON string can be sent to Intune, with the Graph
    performing the validation on the the JSON payload.

    Any attributes that have null or empty string values are filtered out from being sent to Graph. This is because
    the Graph can insert default values when no set values have been placed in the payload.

    Users should authenticate themselves through the SDK first by running Connect-MSGraph, which will then allow
    them to use this cmdlet.

    .LINK
    https://docs.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windowsfirewallrule?view=graph-rest-beta
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(ValueFromPipeline = $true)]
        $firewallObjects,

        [Parameter(Mandatory = $false)]
        [String]
        $migratedProfileName = $Strings.SendIntuneFirewallRulesPolicyProfileNameDefault,

        # If this flag is toggled, then telemetry is automatically sent to Microsoft.
        [switch]
        $sendIntuneFirewallTelemetry,

        # If this flag is toogled, then firewall rules would be imported to Device Configuration else it would be import to device intent
        [switch]
        $DeviceConfiguration

    )

    Begin { $firewallArr = @() }

    # We apply a filter that strips objects of their null attributes so that Graph can
    # apply default values in the absence of set values
    Process {
        $object = $_
        $allProperties = $_.PsObject.Properties.Name
        $nonNullProperties = $allProperties.Where( { $null -ne $object.$_ -and $object.$_ -ne "" })
        $firewallArr += $object | Select-Object $nonNullProperties
    }

    End {
        # Split the incoming firewall objects into separate profiles
        $profiles = @()
        $currentProfile = @()
        $sentSuccessfully = @()
        $failedToSend = @()
        ForEach ($firewall in $firewallArr) {
            If ($currentProfile.Count -ge $ProfileFirewallRuleLimit) {
                # Arrays may be "unrolled", so we need to enforce no unrolling
                $profiles += , $currentProfile 
                $currentProfile = @()
            }
            $currentProfile += $firewall
            
        }
        If ($currentProfile.Count -gt 0 ) {
            # Arrays may be "unrolled", so we need to enforce no unrolling
            $profiles += , $currentProfile
        }
        $profileNumber = 0

        $remainingProfiles = $profiles.Count
        $date = Get-Date
        $dateformatted = Get-Date -Format "M_dd_yy"
        $responsePath = "./logs/http_response " + $dateformatted + ".txt"
        $payloadPath = "./logs/http_payload " + $dateformatted + ".txt"
        if (-not(Test-Path "./logs")) {
            $item = New-Item "./logs" -ItemType Directory
        }
        #$profiles
        ForEach ($profile in $profiles) {
            $ruleCollector = @()
            #$profile.displayName
            # remainingProfiles is decremented after displaying operation status
            $remainingProfiles = Show-OperationProgress `
                -remainingObjects $remainingProfiles `
                -totalObjects $profiles.Count `
                -activityMessage $Strings.SendIntuneFirewallRulesPolicyProgressStatus
            #---------------------------------------------------------------------------------
            $textHeader = ""
            $NewIntuneObject = ""
            if ($DeviceConfiguration) {
                $textHeader = "Device Configuration Payload"
                $profileJson = $profile | ConvertTo-Json
                $NewIntuneObject = "{
                    `"@odata.type`": `"#microsoft.graph.windows10EndpointProtectionConfiguration`",
                    `"displayName`": `"$migratedProfileName-$profileNumber`",
                    `"firewallRules`": $profileJson,
                       }"
            }
            else {
                $textHeader = "End-Point Security Payload"
                $profileAsString = "["
                $staticChildrenCollection = @()
                $counter = 0
                ForEach ($rules in $profile) {
                    if(!($rules.displayName -in $ruleCollector)) {
                        $ruleCollector += $rules.displayName
                    }
                    else {
                        $rules.displayName = $rules.displayName + "_" + $counter
                        $counter++
                        $ruleCollector += $rules.displayName
                    }
                    #$rules.displayName
                    $staticChildren = @()
                    if ($profile.IndexOf($rules) -eq $profile.Length - 1) {
                        $profileAsString += (ConvertTo-IntuneFirewallRuleString $rules) + "]"
                    }
                    else {
                        $profileAsString += (ConvertTo-IntuneFirewallRuleString $rules) + ","
                    }

                    if ($rules.protocol) {
                        $staticProtocolValue = [PSCustomObject]@{
                            "@odata.type" = "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue"
                            "value"       = $rules.protocol
                        }
                        $staticChildren += [PSCustomObject]@{
                            "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_protocol"
                            "simpleSettingValue"  = $staticProtocolValue
                        }
                    }
                    if ($rules.displayName) {
                        $staticNameValue = [PSCustomObject]@{
                            "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                            "value"       = $rules.displayName
                        }
                        $staticChildren += [PSCustomObject]@{
                            "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_name"
                            "simpleSettingValue"  = $staticNameValue
                        }
                    }
                    if ($rules.filepath) {
                        $staticPathValue = [PSCustomObject]@{
                            "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                            "value"       = $rules.filePath
                        }
                        $staticChildren += [PSCustomObject]@{
                            "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_app_filepath"
                            "simpleSettingValue"  = $staticPathValue
                        }
                    }
                    if ($rules.servicename) {
                        $staticServiceValue = [PSCustomObject]@{
                            "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                            "value"       = $rules.servicename
                        }
                        $staticChildren += [PSCustomObject]@{
                            "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_app_servicename"
                            "simpleSettingValue"  = $staticServiceValue
                        }
                    }
                    if ($rules.edgeTraversal) {
                        switch ($rules.edgeTraversal) {
                            allowed {
                                $staticEdgeTraversalValue = [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_edgetraversal_1"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                                    "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_edgetraversal"
                                    "choiceSettingValue"  = $staticEdgeTraversalValue
                                }
                            }
                            blocked {
                                $staticEdgeTraversalValue = [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_edgetraversal_0"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                                    "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_edgetraversal"
                                    "choiceSettingValue"  = $staticEdgeTraversalValue
                                }
                            }
                            default {

                            }
                        }
                    }
                    if ($rules.profileTypes) {
                        switch ($rules.profileTypes) {
                            0 {}
                            1 {
                                $staticProfileValue = @()
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_1"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance"
                                    "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles"
                                    "choiceSettingCollectionValue" = $staticProfileValue
                                }
                            }
                            2 {
                                $staticProfileValue = @()
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_2"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance"
                                    "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles"
                                    "choiceSettingCollectionValue" = $staticProfileValue
                                }
                            }
                            3 {
                                $staticProfileValue = @()
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_1"
                                }
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_2"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance"
                                    "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles"
                                    "choiceSettingCollectionValue" = $staticProfileValue
                                }
                            }
                            4 {
                                $staticProfileValue = @()
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_4"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance"
                                    "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles"
                                    "choiceSettingCollectionValue" = $staticProfileValue
                                }
                            }
                            5 {
                                $staticProfileValue = @()
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_1"
                                }
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_4"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance"
                                    "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles"
                                    "choiceSettingCollectionValue" = $staticProfileValue
                                }
                            }
                            6 {
                                $staticProfileValue = @()
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_2"
                                }
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_4"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance"
                                    "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles"
                                    "choiceSettingCollectionValue" = $staticProfileValue
                                }
                            }
                            7 {
                                $staticProfileValue = @()
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_1"
                                }
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_2"
                                }
                                $staticProfileValue += [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles_4"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance"
                                    "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_profiles"
                                    "choiceSettingCollectionValue" = $staticProfileValue
                                }
                            }
                        }
                    }
                    if ($rules.trafficDirection) {
                        switch ($rules.trafficDirection) {
                            in {
                                $staticDirectionValue = [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_direction_in"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                                    "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_direction"
                                    "choiceSettingValue"  = $staticDirectionValue
                                }
                            }
                            out {
                                $staticDirectionValue = [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_direction_out"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                                    "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_direction"
                                    "choiceSettingValue"  = $staticDirectionValue
                                }
                            }
                            default {}
                        }
                    }
                    if ($rules.action) {
                        switch ($rules.action) {
                            allowed {
                                $staticActionValue = [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_action_type_1"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                                    "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_action_type"
                                    "choiceSettingValue"  = $staticActionValue
                                }
                            }
                            blocked {
                                $staticActionValue = [PSCustomObject]@{
                                    "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_action_type_0"
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                                    "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_action_type"
                                    "choiceSettingValue"  = $staticActionValue
                                }
                            }
                            default {}
                        }
                    }
                    if ($rules.description) {
                        $staticDescriptionvalue = [PSCustomObject]@{
                            "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                            "value"       = $rules.description
                        }
                        $staticChildren += [PSCustomObject]@{
                            "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_description"
                            "simpleSettingValue"  = $staticDescriptionvalue
                        }
                    }
                    if ($rules.localPortRanges) {
                        switch ($rules.localPortRanges.count) {
                            1 {
                                $staticLocalPortValue = @()
                                $staticLocalPortValue += [PSCustomObject]@{
                                    "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                    "value"       = $rules.localPortRanges[0]
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance"
                                    "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_localportranges"
                                    "simpleSettingCollectionValue" = $staticLocalPortValue
                                }
                            }
                            Default {
                                $staticLocalPortValue = @()
                                for ($j = 0; $j -lt $rules.localPortRanges.count; $j++) {
                                    $staticLocalPortValue += [PSCustomObject]@{
                                        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                        "value"       = $rules.localPortRanges[$j]
                                    }
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance"
                                    "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_localportranges"
                                    "simpleSettingCollectionValue" = $staticLocalPortValue
                                }
                            }
                        }
                    }
                    if ($rules.actualRemoteAddressRanges) {
                        switch ($rules.actualRemoteAddressRanges.count) {
                            1 {
                                $staticRemoteAddressValue = @()
                                $staticRemoteAddressValue += [PSCustomObject]@{
                                    "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                    "value"       = $rules.actualRemoteAddressRanges[0]
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance"
                                    "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_remoteaddressranges"
                                    "simpleSettingCollectionValue" = $staticRemoteAddressValue
                                }
                            }
                            Default {
                                $staticRemoteAddressValue = @()
                                foreach ($remoteIp in $rules.actualRemoteAddressRanges) {
                                    $staticRemoteAddressValue += [PSCustomObject]@{
                                        "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                                        "value"       = $remoteIp
                                    }
                                }
                                $staticChildren += [PSCustomObject]@{
                                    "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance"
                                    "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_remoteaddressranges"
                                    "simpleSettingCollectionValue" = $staticRemoteAddressValue
                                }
                            }
                        }
                    }
                    if ($rules.packageFamilyName) {
                        $staticPackageName = [PSCustomObject]@{
                            "@odata.type" = "#microsoft.graph.deviceManagementConfigurationStringSettingValue"
                            "value"       = $rules.packageFamilyName
                        }
                        $staticChildren += [PSCustomObject]@{
                            "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance"
                            "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_app_packagefamilyname"
                            "simpleSettingValue"  = $staticPackageName
                        }
                    }

                    #Rule enabled or not
                    $staticEnabledValue = [PSCustomObject]@{
                        "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_enabled_1"
                    }
                    $staticChildren += [PSCustomObject]@{
                        "@odata.type"         = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                        "settingDefinitionId" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_enabled"
                        "choiceSettingValue"  = $staticEnabledValue
                    }

                    #Interface type
                    $staticInterfaceValue = @()
                    $staticInterfaceValue += [PSCustomObject]@{
                        "value" = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_interfacetypes_all"
                    }
                    $staticChildren += [PSCustomObject]@{
                        "@odata.type"                  = "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance"
                        "settingDefinitionId"          = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}_interfacetypes"
                        "choiceSettingCollectionValue" = $staticInterfaceValue
                    }

                    $staticChildrenCollection += [pscustomobject]@{
                        "children" = $staticChildren
                    }
                }

                $staticInstanceId = [PSCustomObject]@{
                    "settingInstanceTemplateId" = "76c7a8be-67d2-44bf-81a5-38c94926b1a1"
                }

                $staticGroupCollection = [PSCustomObject]@{
                    "@odata.type"                      = "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance"
                    "settingDefinitionId"              = "vendor_msft_firewall_mdmstore_firewallrules_{firewallrulename}"
                    "groupSettingCollectionValue"      = $staticChildrenCollection
                    "settingInstanceTemplateReference" = $staticInstanceId
                }

                $staticSettingsJson = @()
                $staticSettingsJson += [pscustomobject]@{
                    "@odata.type"   = "#microsoft.graph.deviceManagementConfigurationSetting"
                    settingInstance = $staticGroupCollection
                }

                $staticTemplateId = [PSCustomObject]@{
                    "templateId" = "19c8aa67-f286-4861-9aa0-f23541d31680_1"
                }

                $global:staticJson = [pscustomobject]@{
                    name              = "$($migratedProfileName)-$($profileNumber)"
                    description       = "$($migratedProfileName)-$($profileNumber)"
                    platforms         = "windows10"
                    technologies      = "mdm,microsoftSense"
                    settings          = $staticSettingsJson
                    templateReference = $staticTemplateId
                }

                $bodyObject = $global:staticJson | ConvertTo-Json -Depth 100

                $profileJson = $profileAsString | ConvertTo-Json
                $NewIntuneObject = "{
                                    `"description`" : `"Migrated firewall profile created on $date`",
                                    `"displayName`" : `"$migratedProfileName-$profileNumber`",
                                    `"roleScopeTagIds`" :[],
                                    `"settingsDelta`" : [{
                                                        `"@odata.type`": `"#microsoft.graph.deviceManagementCollectionSettingInstance`",
                                                        `"definitionId`" : `"deviceConfiguration--windows10EndpointProtectionConfiguration_firewallRules`",
                                                        `"valueJson`" : $profileJson  
                                                    }]
                                    }"
            }
            If ($PSCmdlet.ShouldProcess($NewIntuneObject, $Strings.SendIntuneFirewallRulesPolicyShouldSendData)) {
                Try {
                    
                    if ($DeviceConfiguration) {
                        #$successResponse = Invoke-MSGraphRequest -Url 'https://graph.microsoft.com/beta/devicemanagement/deviceconfigurations/' -HttpMethod POST -Content $NewIntuneObject
                        #$successMessage = "`r`n$migratedProfileName-$profileNumber has been successfully imported to Intune (Device Configuration)`r`n"
                    }
                    else {
                        $successResponse = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Body $bodyObject -Headers $Global:authHeader -ContentType application/json
                        #$successResponse = Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceManagement/templates/4356d05c-a4ab-4a07-9ece-739f7c792910/createInstance" -HttpMethod POST -Content $NewIntuneObject
                        #$successResponse = Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -HttpMethod POST -Content $bodyObject
                        $successMessage = "`r`n$migratedProfileName-$profileNumber has been successfully imported to Intune (End-Point Security)`r`n"
                    }
                     

                    Write-Verbose $successResponse
                    Write-Verbose  $NewIntuneObject
                    Add-Content  $responsePath "`r `n $date `r `n $s$successMessage `r `n $successResponse"
            
                    
                    $profileNumber++
                    $sentSuccessfully += Get-ExcelFormatObject -intuneFirewallObjects $profile
                    
                }
                Catch {

                    
                    # Intune Graph errors are telemetry points that can detect payload mistakes
                    $errorMessage = $_.ToString()
                    Write-Host $errorMessage -ForegroundColor Red
                    $errorType = $_.Exception.GetType().ToString()
                    if ($sendIntuneFirewallTelemetry) {
                        $choice = Get-IntuneFirewallRuleErrorTelemetryChoice -telemetryMessage $errorMessage `
                            -sendErrorTelemetryInitialized $sendIntuneFirewallTelemetry `
                            -telemetryExceptionType $errorType
                    }
                    else {
                        $choice = $Strings.Continue
                    }
                   
                    switch ($choice) {
                        $Strings.Yes { Send-IntuneFirewallGraphTelemetry -data $errorMessage }
                        $Strings.No { Throw $Strings.SendIntuneFirewallRulesPolicyException }
                        $Strings.YesToAll {
                            Send-IntuneFirewallGraphTelemetry -data $errorMessage
                            $sendIntuneFirewallTelemetry = $true
                        }
                        $Strings.Continue { continue }
                    }
                    $failedToSend += Get-ExcelFormatObject -intuneFirewallObjects $profile -errorMessage $errorMessage
                 
                    Add-Content $responsePath "`r `n $date `r `n $errorMessage"
                }
            }
            Add-Content  $payloadPath "`r `n$date `r `n$textHeader `r `n$NewIntuneObject `r `r `ndevConfigv2 json body `n$bodyObject"
        }
        
        #$dataTelemetry = "{0}/{1} Intune Firewall Rules were successfully imported to Endpoint-Security" -f $sentSuccessfully.Count, $firewallArr.Count
        Export-ExcelFile -fileName "Imported_to_Intune" -succeededToSend $sentSuccessfully 
        #Send-SuccessIntuneFirewallGraphTelemetry -data  $dataTelemetry
        Export-ExcelFile -fileName "Failed_to_Import_to_Intune" -failedToSend $failedToSend
        Set-SummaryDetail -numberOfSplittedRules $firewallArr.Count -ProfileName $migratedProfileName -successCount $sentSuccessfully.Count 
        Get-SummaryDetail
    }
}
