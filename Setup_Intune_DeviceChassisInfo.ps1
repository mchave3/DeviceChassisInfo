<#
.SYNOPSIS
This script creates the Microsoft Entra groups, the device categories and the proactive remediation scripts required to set the device category based on the chassis type.

.DESCRIPTION
The script creates the Microsoft Entra groups, the device categories and the proactive remediation scripts required to set the device category based on the chassis type.

.PARAMETER tenantID
The ID of the Microsoft Entra tenant where the App Registration is created.

.PARAMETER clientID
The ID of the App Registration.

.PARAMETER clientsecret
The secret key of the App Registration.

.EXAMPLE
.\Setup_Intune_DeviceChassisInfo.ps1

This example runs the script and creates the Microsoft Entra groups, the device categories and the proactive remediation scripts required to set the device category based on the chassis type.

.NOTES
Author: Mickael CHAVE
Date: 11/01/2024
Version: 1.0
#>

BEGIN{
    # ============================================================
    # IMPORTANT: FILL IN THE APP REGISTRATION AND TENANT ID DETAILS
    # ============================================================

    # App Registration details
    $global:tenantID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    $global:clientID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    $global:clientsecret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

    # ============================================================
    
    # Log file details
    $global:logdir = "C:\Windows\Temp"
    $global:logfile = "$global:logdir\Setup_Intune_DeviceChassisInfo.log"

    # Microsoft Intune remediation name
    $global:remediationName = "DeviceChassisInfo Remediation Solution"

    # Device groups to create
    $global:EntraGroups = @(
        @{
            Name="Clients - ChassisType - Desktops"; 
            Description="This Microsoft Entra group is dynamically grouping all machines with the device category 'Desktops'."; 
            MembershipRule="device.deviceCategory -eq `"Desktop`""; # DO NOT EDIT THIS LINE
            MailNickname="ChassisType-Desktops"},
        @{
            Name="Clients - ChassisType - Laptops"; 
            Description="This Microsoft Entra group is dynamically grouping all machines with the device category 'Laptops'."; 
            MembershipRule="device.deviceCategory -eq `"Laptop`""; # DO NOT EDIT THIS LINE
            MailNickname="ChassisType-Laptops"},
        @{
            Name="Clients - ChassisType - Tablets"; 
            Description="This Microsoft Entra group is dynamically grouping all machines with the device category 'Tablets'."; 
            MembershipRule="device.deviceCategory -eq `"Tablet`""; # DO NOT EDIT THIS LINE
            MailNickname="ChassisType-Tablets"},
        @{
            Name="Clients - ChassisType - Unknown Device"; 
            Description="This Microsoft Entra group is dynamically grouping all machines with the device category 'Unknown Device'."; 
            MembershipRule="device.deviceCategory -eq `"Unknown Device`""; # DO NOT EDIT THIS LINE
            MailNickname="ChassisType-UnknownDevice"},
        @{
            Name="Clients - ChassisType - Virtual Machine"; 
            Description="This Microsoft Entra group is dynamically grouping all machines with the device category 'Virtual Machine'."; 
            MembershipRule="device.deviceCategory -eq `"Virtual Machine`""; # DO NOT EDIT THIS LINE
            MailNickname="ChassisType-VirtualMachine"}
    )

    # ============================================================
    # DO NOT MODIFY ANYTHING BELOW THIS LINE
    # ============================================================

    # Set the Graph API base URL and version
    $global:graphApiBaseUrl = "https://graph.microsoft.com"
    $global:graphApiversion = "beta"

    # Set the device categories
    $global:deviceCategories = @(
        @{
            Name='Desktop';
            Description='This device category is used for identifying desktops.'
        }
        @{
            Name='Laptop';
            Description='This device category is used for identifying laptops.'
        }
        @{
            Name='Tablet';
            Description='This device category is used for identifying tablets.'
        }
        @{
            Name='Unknown Device';
            Description='This device category is used for identifying unknown devices.'
        }
        @{
            Name='Virtual Machine';
            Description='This device category is used for identifying virtual machines.'
        }
    )

    # Check if the script is running as administrator
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "Please run the script as administrator."
        Write-Host "Press enter to exit..."
        $null = Read-Host
        exit
    }
}

PROCESS{
    # Function for logging
    Function LogWrite
    {
        Param ([string]$logstring)
        $logstring = (Get-Date).ToString() + " - $logstring"
        Add-Content $global:logfile -Value $logstring
        
        if ($logstring -like "*Error:*") {
            Write-Host $logstring -ForegroundColor Red
        }
        else {
            Write-Host $logstring
        }
    }

    # Function for exiting the script
    Function ExitScript
    {
        LogWrite "Script stopped with errors."
        LogWrite "Log file: $global:logfile"
        Write-Host "Press enter to exit..."
        $null = Read-Host
        exit
    }

    ########################################################
    # Main Script

    LogWrite "Script starting..."

##############################################################################################################################################################################
# Check if App Registration details are filled in
##############################################################################################################################################################################

    try {
        if ($global:tenantID -eq $null -or $global:tenantID -eq "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -or 
            $global:clientID -eq $null -or $global:clientID -eq "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -or 
            $global:clientsecret -eq $null -or $global:clientsecret -eq "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") {
            throw "Please fill in the App Registration and Tenant ID details in the script."
        }
    }
    catch {
        LogWrite "Error: $($_.Exception.Message)"
        ExitScript
    }

##############################################################################################################################################################################
# Install and import required modules
##############################################################################################################################################################################

    # Set the modules to install
    $modules = @(
        @{Name='NuGet'; Version='2.8.5.201'; IsPackageProvider=$true},
        @{Name='Microsoft.Graph.Authentication'}
    )

    # Install modules
    foreach ($module in $modules){
        if($module.IsPackageProvider -eq $true)
        {
            try {
                # Get all versions of the provider installed on the machine
                $installedProviderVersions = Get-PackageProvider -ListAvailable -Name $module.Name
            }
            catch { 
                # Do nothing for not showing up the error message when the provider is not installed
            }
        }
        try{
            # Check if the module is a package provider
            if ($module.IsPackageProvider -eq $true) {
                # If the provider is installed
                if ($installedProviderVersions){
                    # Find the latest version available online
                    $onlineProviderVersion = [version](Find-PackageProvider -Name $module.Name).Version

                    # Find the latest version installed on the machine
                    $latestInstalledProviderVersion = [version]($installedProviderVersions | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()

                    # If the online version is newer than the latest installed version
                    if ($onlineProviderVersion -gt $latestInstalledProviderVersion){
                        LogWrite "A newer version of $($module.Name) is available online. Updating..."
                        Install-PackageProvider $module.Name -Force -Scope AllUsers -MinimumVersion $module.Version
                        LogWrite "Package provider $($module.Name) updated to version $($onlineProviderVersion)."
                    }
                    else{
                        LogWrite "Package provider $($module.Name) is up to date."
                    }
                }
                # If the provider is not installed, install it
                else{
                    LogWrite "Package provider $($module.Name) is not installed. Installing..."
                    Install-PackageProvider $module.Name -Force -Scope AllUsers -MinimumVersion $module.Version
                    LogWrite "Package provider $($module.Name) installed."
                }
            } else {
                # Get all versions of the module installed on the machine
                $installedVersions = Get-Module -ListAvailable -Name $module.Name

                # If the module is installed
                if ($installedVersions){
                    # Find the latest version available online
                    $onlineVersion = [version](Find-Module -Name $module.Name).Version

                    # Find the latest version installed on the machine
                    $latestInstalledVersion = [version]($installedVersions | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()

                    # If the online version is newer than the latest installed version
                    if ($onlineVersion -gt $latestInstalledVersion){
                        LogWrite "A newer version of $($module.Name) is available online. Updating..."
                        Update-Module $module.Name -Force -Scope AllUsers
                        LogWrite "Module $($module.Name) updated to version $($onlineVersion)."
                    }
                    else{
                        LogWrite "Module $($module.Name) is up to date."
                    }
                }
                # If the module is not installed, install it
                else{
                    LogWrite "Module $($module.Name) is not installed. Installing..."
                    Install-Module $module.Name -Force -Scope AllUsers
                    LogWrite "Module $($module.Name) installed."
                }
            }
        }
        catch{
            LogWrite "Error installing or updating module $($module.Name). Error: $($_.Exception.Message)"
            ExitScript
        }
    }

    # Import modules
    foreach ($module in $modules){
        # Check if not package provider
        if ($module.IsPackageProvider -eq $false) {
            try{
                LogWrite "Importing module $($module.Name)..."
                Import-Module $module.Name -ErrorAction Stop
                LogWrite "Module $($module.Name) imported."
            }
            catch{
                LogWrite "Error importing module $($module.Name). Error: $($_.Exception.Message)"
                ExitScript
            }
        }
    }

##############################################################################################################################################################################
# Microsoft Graph authentication
##############################################################################################################################################################################

    # Set the scopes for Microsoft Graph
    $scopes = @(
        "Group.ReadWrite.All",
        "DeviceManagementConfiguration.ReadWrite.All"
    )

    # Authenticate to Microsoft Graph
    try {
        LogWrite "Authenticating to Microsoft Graph..."
        Connect-MgGraph -Scopes $scopes -NoWelcome
        if (Get-MgContext) {
            LogWrite "Authenticated to Microsoft Graph."
        }
        else {
            throw "Error authenticating to Microsoft Graph."
        }
    }
    catch {
        LogWrite "Error: $($_.Exception.Message)"
        ExitScript
    }

##############################################################################################################################################################################
# Microsoft Entra groups creation
##############################################################################################################################################################################

    # Get all Microsoft Entra groups
    $groups = Invoke-MgGraphRequest -Uri "$($global:graphApiBaseUrl)/$($global:graphApiversion)/groups" -Method Get -ErrorAction Stop

    # Create the Microsoft Entra groups
    foreach ($EntraGroup in $global:EntraGroups) {
        try {
            $group = $groups.value | Where-Object {$_.displayName -eq $EntraGroup.Name}
            # Check if the Microsoft Entra group already exists
            if ($group) {
                LogWrite "Microsoft Entra group '$($EntraGroup.Name)' already exists."
            }
            # If the Microsoft Entra group does not exist, create it
            else {
                $body = @{
                    displayName = $EntraGroup.Name
                    description = $EntraGroup.Description
                    groupTypes = @("DynamicMembership")
                    membershipRule = $EntraGroup.MembershipRule
                    membershipRuleProcessingState = "On"
                    securityEnabled = $true
                    mailEnabled = $false
                    mailNickname = $global:EntraGroup.MailNickname
                }

                # Format the body
                $body = $body | ConvertTo-Json

                $group = Invoke-MgGraphRequest -Uri "$($global:graphApiBaseUrl)/$($global:graphApiversion)/groups" -Method Post -Body $body -ErrorAction Stop
                LogWrite "Microsoft Entra group '$($EntraGroup.Name)' created."
            }
        }
        catch {
            LogWrite "Error creating Microsoft Entra group '$($EntraGroup.Name)'. Error: $($_.Exception.Message)"
            ExitScript
        }
    }

##############################################################################################################################################################################
# Device categories creation
##############################################################################################################################################################################
       
    # Device categories
    foreach ($deviceCategory in $global:deviceCategories) {
        try {
            # Check if the device category already exists
            $deviceCategoryExists = Invoke-MgGraphRequest -Uri "$($global:graphApiBaseUrl)/$($global:graphApiversion)/deviceManagement/deviceCategories" -Method Get -ErrorAction Stop | Where-Object {$_.value.displayName -eq $deviceCategory.Name}
            if ($deviceCategoryExists) {
                LogWrite "Device category '$($deviceCategory.Name)' already exists."
            }
            # If the device category does not exist, create it
            else {
                $body = @{
                    displayName = $deviceCategory.Name
                    description = $deviceCategory.Description
                }
                $body = $body | ConvertTo-Json
                $deviceCategory = Invoke-MgGraphRequest -Uri "$($global:graphApiBaseUrl)/$($global:graphApiversion)/deviceManagement/deviceCategories" -Method Post -Body $body -ErrorAction Stop
                LogWrite "Device category '$($deviceCategory.displayName)' created."
            }
        }
        catch {
            LogWrite "Error creating device category '$($deviceCategory.Name)'. Error: $($_.Exception.Message)"
            ExitScript
        }
    }

##############################################################################################################################################################################
# Proactive remediation scripts
##############################################################################################################################################################################

    # Check if the proactive remediation is already uploaded to Microsoft Intune
    $remediationScripts = Invoke-MgGraphRequest -Uri "$($global:graphApiBaseUrl)/$($global:graphApiversion)/deviceManagement/deviceHealthScripts" -Method Get -ErrorAction Stop | Where-Object {$_.value.displayName -eq $global:remediationName}
    if ($remediationScripts) {
        LogWrite "Proactive remediation already uploaded to Microsoft Intune."
        LogWrite "If you want to upload the proactive remediation again, please delete the proactive remediation from Microsoft Intune and run the script again."
        ExitScript
    }

    # Download the proactive remediation scripts from GitHub and store them in a temporary folder
    $tempFolder = "$env:TEMP\Intune-ChassisType"
    if (!(Test-Path $tempFolder)) {
        New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
    }
    else {
        Remove-Item -Path $tempFolder -Recurse -Force | Out-Null
        New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
    }

    # Table with the remediation scripts
    $remediationScripts = @(
        @{
            Name='DeviceChassisInfo_Detection.ps1';
            Uri='https://raw.githubusercontent.com/mchave3/PowerShell-Scripts/main/Intune/Manage-ChassisType/Remediation/DeviceChassisInfo_Detection.ps1';
            Path="$tempFolder\DeviceChassisInfo_Detection.ps1"
        }
        @{
            Name='DeviceChassisInfo_Remediation.ps1';
            Uri='https://raw.githubusercontent.com/mchave3/PowerShell-Scripts/main/Intune/Manage-ChassisType/Remediation/DeviceChassisInfo_Remediation.ps1';
            Path="$tempFolder\DeviceChassisInfo_Remediation.ps1"
        }
    )

    # Table with the edited remediation scripts
    $editedScripts = @(
        @{
            Name='Edited_DeviceChassisInfo_Detection';
            Content=""
        }
        @{
            Name='Edited_DeviceChassisInfo_Remediation';
            Content=""
        }
    )

    # Download the remediation scripts
    foreach ($remediationScript in $remediationScripts) {
        try {
            LogWrite "Downloading remediation script '$($remediationScript.Name)'..."
            $remediationScriptContent = Invoke-WebRequest -Uri $remediationScript.Uri -ErrorAction Stop
            $remediationScriptContent = $remediationScriptContent.Content
            $remediationScriptContent | Out-File -FilePath $remediationScript.Path -Encoding utf8 -Force
            LogWrite "Remediation script '$($remediationScript.Name)' downloaded."
        }
        catch {
            LogWrite "Error downloading remediation script '$($remediationScript.Name)'. Error: $($_.Exception.Message)"
            ExitScript
        }
    }
    
    # Edit the remediation scripts
    foreach ($remediationScript in $remediationScripts) {
        try {
            LogWrite "Editing remediation script '$($remediationScript.Name)'..."
            $remediationScriptContent = Get-Content -Path $remediationScript.Path -Raw -ErrorAction Stop

            # Replace the first occurrence of "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" with $global:tenantID
            $index = $remediationScriptContent.IndexOf("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
            if ($index -ge 0) {
                $remediationScriptContent = $remediationScriptContent.Remove($index, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".Length).Insert($index, $global:tenantID)
            }

            # Replace the next occurrence of "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" with $global:clientID
            $index = $remediationScriptContent.IndexOf("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
            if ($index -ge 0) {
                $remediationScriptContent = $remediationScriptContent.Remove($index, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".Length).Insert($index, $global:clientID)
            }

            # Replace the first occurrence of "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" with $global:clientsecret
            $index = $remediationScriptContent.IndexOf("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
            if ($index -ge 0) {
                $remediationScriptContent = $remediationScriptContent.Remove($index, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".Length).Insert($index, $global:clientsecret)
            }

            # Remove '.ps1' suffix from the remediation script name
            $remediationScriptName = $remediationScript.Name -replace '.ps1', ''
            
            # Adapt the proactive remediation script content
            foreach ($editedScript in $editedScripts) {
                # Remove 'Edited_' prefix from the edited script name
                $editedScriptName = $editedScript.Name -replace 'Edited_', ''
                
                if ($remediationScriptName -eq $editedScriptName) {

                    # Convert to base64
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($remediationScriptContent)
                    $editedScript.Content = [Convert]::ToBase64String($bytes)

                    LogWrite "Remediation script '$($remediationScript.Name)' edited."
                }
            }
        }
        catch {
            LogWrite "Error editing remediation script '$($remediationScript.Name)'. Error: $($_.Exception.Message)"
            ExitScript
        }
    }

    # Set the proactive remediation body
    $body = @{
        displayName = $global:remediationName
        description = "This proactive remediation script is used to set the device category based on the chassis type."
        publisher = "Mickael CHAVE"
        runAs32Bit = $true
        runAsAccount = "system"
        enforceSignatureCheck = $false
        detectionScriptContent = $editedScripts[0].Content
        remediationScriptContent = $editedScripts[1].Content
        roleScopeTagIds = @("0")
    }

    # Create the proactive remediation
    try {
        $body = $body | ConvertTo-Json
        Invoke-MgGraphRequest -Uri "$($global:graphApiBaseUrl)/$($global:graphApiversion)/deviceManagement/deviceHealthScripts" -Method Post -Body $body -ErrorAction Stop | Out-Null
        LogWrite ""
        LogWrite "Proactive remediation created."
        LogWrite "Please assign the proactive remediation to the required groups in Microsoft Intune."
        LogWrite ""
    }
    catch {
        LogWrite "Error creating proactive remediation. Error: $($_.Exception.Message)"
        ExitScript
    }
}

END{
    # Disconnect from Microsoft Graph
    if (Get-MgContext) {
        try {
            Disconnect-MgGraph | Out-Null
            LogWrite "Disconnected from Microsoft Graph."
        }
        catch {
            LogWrite "Error disconnecting from Microsoft Graph. Error: $($_.Exception.Message)"
            ExitScript
        }
    }

    # Clean up the temporary folder
    try {
        Remove-Item -Path $tempFolder -Recurse -Force
        LogWrite "Temporary folder cleaned up."
    }
    catch {
        LogWrite "Error cleaning up temporary folder. Error: $($_.Exception.Message)"
        ExitScript
    }

    LogWrite "Script completed."
    LogWrite "Log file: $global:logfile"
}