<#
.SYNOPSIS
This script sets the device category of a computer.

.DESCRIPTION
The script connects to Microsoft Graph using the provided App Registration details and retrieves the device chassis type of the computer. It then checks if the device is a known type (e.g., desktop, laptop, tablet) or a virtual machine. If the device category in Intune does not match the detected device type, the script updates the device category.

.PARAMETER tenantID
The ID of the Microsoft Entra tenant where the App Registration is created.

.PARAMETER clientID
The ID of the App Registration.

.PARAMETER clientsecret
The secret key of the App Registration.

.EXAMPLE
.\DeviceChassisInfo_Remediation.ps1

This example runs the script and sets the device category of the computer.
The log file is saved by default in C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DeviceChassisInfo_Remediation.log.

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
    $global:logdir = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
    $global:logfile = "$logdir\DeviceChassisInfo_Remediation.log"

    # ============================================================
    # DO NOT MODIFY ANYTHING BELOW THIS LINE
    # ============================================================

    # Set the Graph API base URL and version
    $global:graphApiBaseUrl = "https://graph.microsoft.com"
    $global:graphApiversion = "beta"
}

PROCESS{
    # Function for logging
    Function LogWrite
    {
        Param ([string]$logstring)
        $logstring = (Get-Date).ToString() + " - $logstring"
        Add-Content $Logfile -Value $logstring
        Write-Host $logstring
    }

    # Function to update the device category
    function Update-DeviceCategory {
        Param
        (
            [Parameter(Mandatory=$true, Position=0)]
            [string] $DeviceID,
            [Parameter(Mandatory=$true, Position=1)]
            [string] $DeviceCategoryID
        )

        try {
            # Define the body for the request
            $bodyCategory = @{
                "@odata.id" = "$global:graphApiBaseUrl/$global:graphApiversion/deviceManagement/deviceCategories/$DeviceCategoryID"
            } | ConvertTo-Json

            # Update the device category
            Invoke-MgGraphRequest -Uri "$global:graphApiBaseUrl/$global:graphApiversion/deviceManagement/managedDevices/$DeviceID/deviceCategory/`$ref" -Method PUT -Body $bodyCategory
            }
        catch {
            LogWrite "Error updating device category. Error: $($_.Exception.Message)"
            LogWrite "Exiting script..."
            exit
        }

        try {
            $device = Invoke-MgGraphRequest -Uri "$global:graphApiBaseUrl/$global:graphApiversion/deviceManagement/managedDevices?`$filter=serialNumber eq '$biosSerialNumberNoSpaces'" -Method Get
        }
        catch {
            LogWrite "Error getting device from Microsoft Graph. Error: $($_.Exception.Message)"
            LogWrite "Exiting script..."
            exit
        }
        
        $count = 1

        # Wait for device category to be set
        while ($count -le 5) {
            LogWrite "Waiting for device category to be set... ($count/5)"
            Start-Sleep -Seconds 30
            
            try {
                $device = Invoke-MgGraphRequest -Uri "$global:graphApiBaseUrl/$global:graphApiversion/deviceManagement/managedDevices?`$filter=serialNumber eq '$biosSerialNumberNoSpaces'" -Method Get
            }
            catch {
                LogWrite "Error getting device from Microsoft Graph. Error: $($_.Exception.Message)"
                LogWrite "Exiting script..."
                exit
            }

            $count++

            # Check if device category is set correctly and exit the loop if it is
            if ($device.value.deviceCategoryDisplayName -eq $deviceType) {
                break
            }
        }
        # If device category is not set after 5 minutes, log a warning
        if ($count -eq 6) {
            LogWrite "Waiting time exceeded. Intune may take longer than expected."
        }
        # Else, log a success message
        else {
            LogWrite "Device Category set successfully !"
        }
    }

    ########################################################
    # Main Script

    LogWrite "Script starting..."

    # Get Windows version
    $Computer = Get-ComputerInfo | Select-Object OSName,OSDisplayVersion,CsName
    LogWrite "Current OS : $($Computer.OsName) $($Computer.OSDisplayVersion)"

##############################################################################################################################################################################
# Check if App Registration details are filled in
##############################################################################################################################################################################

    # Check if App Registration details are filled in
    try {
        if ($global:tenantID -eq $null -or $global:tenantID -eq "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -or 
            $global:clientID -eq $null -or $global:clientID -eq "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -or 
            $global:clientsecret -eq $null -or $global:clientsecret -eq "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") {
            throw "Please fill in the App Registration and Tenant ID details in the script."
        }
    }
    catch {
        LogWrite "Error: $($_.Exception.Message)"
        LogWrite "Exiting script..."
        exit
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
            LogWrite "Exiting script..."
            exit
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
                LogWrite "Exiting script..."
                exit
            }
        }
    }

##############################################################################################################################################################################
# Microsoft Graph authentication
##############################################################################################################################################################################

    # Set the body for the OAuth request
    $body = @{
        Grant_Type    = "client_credentials"
        Scope         = "https://graph.microsoft.com/.default"
        Client_Id     = $global:clientID
        Client_Secret = $global:clientsecret
    }

    # Connect to Microsoft Graph using the App Registration
    try {
        LogWrite "Connecting to Microsoft Graph..."

        # Get the OAuth token
        $oauth = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$global:tenantID/oauth2/v2.0/token" -Method POST -Body $body
        $accessToken = $oauth.access_token | ConvertTo-SecureString -AsPlainText -Force

        # Connect to Microsoft Graph
        Connect-MgGraph -AccessToken $accessToken -NoWelcome
        LogWrite "Connected to Microsoft Graph."
    }
    catch {
        LogWrite "Error connecting to Microsoft Graph. Error: $($_.Exception.Message)"
        LogWrite "Exiting script..."
        exit
    }

##############################################################################################################################################################################
# Check and update device category
##############################################################################################################################################################################

    # Get the device type
    $deviceTypes = @{
        3 = "Desktop"
        4 = "Desktop"
        5 = "Desktop"
        6 = "Desktop"
        7 = "Desktop"
        8 = "Laptop"
        9 = "Laptop"
        10 = "Laptop"
        11 = "Laptop"
        12 = "Laptop"
        14 = "Laptop"
        15 = "Desktop"
        16 = "Desktop"
        18 = "Laptop"
        21 = "Laptop"
        30 = "Tablet"
        31 = "Laptop"
        32 = "Laptop"
    }

    # Check if unknown device type
    $deviceTypeNumber = (Get-CimInstance -ClassName Win32_SystemEnclosure).ChassisTypes[0]
    $deviceType = $deviceTypes[[int]$deviceTypeNumber]
    if ($null -eq $deviceType) {
        $deviceType = "Unknown Device"
    }

    $virtualMachineIdentifiers = @(
        "Virtual Machine",
        "VMware",
        "VirtualBox",
        "KVM",
        "Xen",
        "Bochs",
        "QEMU",
        "Parallels",
        "Hyper-V")

    # Check if Virtual Machine
    $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem
    foreach ($identifier in $virtualMachineIdentifiers) {
        if ($systemInfo.Manufacturer -like "*$identifier*" -or $systemInfo.Model -like "*$identifier*") {
            $deviceType = "Virtual Machine"
            break
        }
    }

    LogWrite "This device is a $($deviceType)."

    # Get the serial number of the computer
    $serialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    $biosSerialNumberNoSpaces = $serialNumber.Replace(" ", "")

    # Get the device from Microsoft Graph
    try {
        $devices = Invoke-MgGraphRequest -Uri "$global:graphApiBaseUrl/$global:graphApiversion/deviceManagement/managedDevices?`$filter=serialNumber eq '$biosSerialNumberNoSpaces'" -Method Get
    }
    catch {
        LogWrite "Error getting device from Microsoft Graph. Error: $($_.Exception.Message)"
        LogWrite "Exiting script..."
        exit
    }

    # Get the device category from Microsoft Graph
    try {
        $DeviceCategory = Invoke-MgGraphRequest -Uri "$global:graphApiBaseUrl/$global:graphApiversion/deviceManagement/deviceCategories?`$filter=displayName eq '$deviceType'" -Method Get
    }
    catch {
        LogWrite "Error getting device category from Microsoft Graph. Error: $($_.Exception.Message)"
        LogWrite "Exiting script..."
        exit
    }

    # Check if no device is found
    if ($devices.'@odata.count' -eq 0) {
        LogWrite "No device found in Intune."
    }
    # Check if multiple devices are found
    if ($devices.'@odata.count' -gt 1) {
        LogWrite "Multiple devices with same serial number ""$biosSerialNumberNoSpaces"" found !"
        LogWrite "$($devices.'@odata.count') devices found in Microsoft Intune..."
        # Loop through the devices
        foreach ($device in $devices) {
            # Check if the device name matches the computer name
            if ($device.value.deviceName -eq $Computer.CsName) {
                # Update the device category
                Update-DeviceCategory -DeviceID $device.value.id -DeviceCategoryID $DeviceCategory.value.id
            }
            else {
                LogWrite "Current computer name ""$($Computer.CsName)"" does not match with ""$($device.value.deviceName)"" present in Intune."
            }
        }
    }
    # Check if only one device is found
    if ($devices.'@odata.count' -eq 1) {
        # Update the device category
        Update-DeviceCategory -DeviceID $devices.value.id -DeviceCategoryID $DeviceCategory.value.id
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
            LogWrite "Exiting script..."
            exit
        }
    }

    LogWrite "Script completed."
}