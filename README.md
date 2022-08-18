# windows-Defender-firewall-migration-tool
Repository hosting toolset for migrating Windows Defender Firewall rules from Group Policy &amp; Local Store to Microsoft Endpoint Manager aka Microsoft Intune

### How to use the tool?
To migrate Windows Defender Firewall rules to Endpoint Manager, you need to run the tool on a reference machine. The tool can migrate both Local Store rules and rules deployed from Group Policy. Certain prerequisites should be in place before running this tool.

#### Prerequisites
* [An Azure AD app with Delegated Graph API Permission to “DeviceManagementConfiguration.ReadWrite.All](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-configure-app-access-web-apis#delegated-permission-to-microsoft-graph)

> * Make sure to set the `Redirect URI` for Web as `https://localhost`.
> * Enable ‘Access tokens’ under Implicit grant and hybrid flows.
> * Toggle ‘Enable the following mobile & desktop flows’ to yes under allow public client flows. Make a note of the `Application (Client) ID` and `Directory (Tenant) ID`.

* In the script repository, add the `Application (Client) ID` and `Directory (tenant) ID` of the application you created earlier as comma-separated values into the `client.config` file.

#### Switches supported by the tool
Use the following switches (parameters) to modify the tool’s default behavior.

* **IncludeLocalRules** — Use this switch to include all locally created/default Windows firewall rules in the export. Use of this switch can result in a large count of included rules.
* **IncludedDisabledRules** — e this switch to include all enabled and disabled Windows firewall rules in the export. Use of this switch can result in a large count of included rules.