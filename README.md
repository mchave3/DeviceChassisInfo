# How to Use

This guide provides detailed instructions on how to utilize the Microsoft Intune Chassis Type script. Whether you prefer an automated setup or a more hands-on, manual configuration, this guide covers both options.

## Prerequisites

Before you begin, ensure that the following prerequisites are in place:

- PowerShell 5 or higher installed on your machine
- Microsoft Entra account with administrative permissions
- App registration on Microsoft Entra

### Create an App Registration

1) Navigate to [Microsoft Entra Portal](https://portal.azure.com/) -> **App registrations**
2) Click on "**New registration**" and enter the following information:
    - **Name:** _The name of this application_
    - **Supported account types:** _Accounts in this organizational directory only_

3) Create a client secret:
    - On the side menu, go to "**Certificates & secrets**" -> "**Client secrets**" -> "**New client secret**"

4) Assign API permissions:
    - On the side menu, go to "**API permissions**" -> "**Add a permission**" and enter the following permissions:

        - _DeviceManagementConfiguration.ReadWrite.All_
        - _DeviceManagementManagedDevices.ReadWrite.All_
        - _Group.ReadWrite.All_

    - Then, click on "**Grant admin consent for (your tenant)**"

# Option 1 - Automatic tenant configuration

This option automatically configures your Microsoft Tenant comprehensively. The provided script handles tasks such as **creating Microsoft Entra Groups**, **Microsoft Intune device categories**, and **uploading proactive remediation**.

## Step 1: Download the Script

To get started, download the [`Setup_Intune_DeviceChassisInfo.ps1`](https://github.com/mchave3/DeviceChassisInfo/blob/main/Setup_Intune_DeviceChassisInfo.ps1) script from the [GitHub repository](https://github.com/mchave3/DeviceChassisInfo).


## Step 2: Configure Script Parameters

Open `Setup_Intune_DeviceChassisInfo.ps1` in a text editor and modify the following parameters:

```powershell
$global:tenantID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$global:clientID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$global:clientsecret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

## Step 3: Execute the Script

_Ensure that you execute this script with administrative privileges._

# Option 2 - Manual tenant configuration

This option provides a more hands-on approach, allowing you to manually set up your Microsoft Azure environment.

## Step 1: Create Microsoft Entra Groups

1) Navigate to **[Microsoft Entra](https://portal.azure.com/)** -> Groups
2) Select "**New group**" and provide the following details:
    - **Group type:** _Security_
    - **Name:** _Clients - ChassisType - Laptops_
    - **Description:** _The description of the group_
    - **Membership type:** _Dynamic Device_
    - **Dynamic device members -> Add dynamic query:** _(Rule builder or Rule syntax)_
        - **Rule builder:**
            - **Property:** _deviceCategory_
            - **Operator:** _Equals_
            - **Value:** _Laptop_
        - **Rule syntax:** _(device.deviceCategory -eq "Laptop")_

3) Repeat this process for each group you intend to create:

    - _Desktop_
    - _Laptop_
    - _Tablet_
    - _Unknown Device_
    - _Virtual Machine_

## Step 2: Create Microsoft Intune Device Categories

1) Navigate to **[Microsoft Intune](https://endpoint.microsoft.com/)** -> **Devices** -> **Device categories**
2) Click on “**Create device category**” and enter the following information:

    - **Name:** _Laptop_
    - **Description:** _This device category is used for all laptops._

3) Repeat this step for each device category:

    - _Desktop_
    - _Laptop_
    - _Tablet_
    - _Unknown Device_
    - _Virtual Machine_

## Step 3: Download Detection & Remediation Scripts

1) To get started, download the detection & remediation script from the [GitHub repository](https://github.com/mchave3/DeviceChassisInfo/tree/main/Remediation).

    - Detection -> [`DeviceChassisInfo_Detection.ps1`](https://github.com/mchave3/DeviceChassisInfo/blob/main/Remediation/DeviceChassisInfo_Detection.ps1) 
    - Remediation -> [`DeviceChassisInfo_Remediation.ps1`](https://github.com/mchave3/DeviceChassisInfo/blob/main/Remediation/DeviceChassisInfo_Remediation.ps1) 

2) Open `DeviceChassisInfo_Detection.ps1` & `DeviceChassisInfo_Remediation.ps1` in a text editor and modify the following parameters:

    ```powershell
    $global:tenantID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    $global:clientID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    $global:clientsecret = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    ```

## Step 4: Create and Assign Proactive Remediation Scripts

1) Navigate to **[Microsoft Intune](https://endpoint.microsoft.com/)** -> **Devices** -> **Remediations**
2) Click on “**Create script package**” and enter the following information:

    - **Name:** _Specify the name of the script package_
    - **Description:** _Provide a description for the script package_
    - **Publisher:** _Indicate the publisher of the script package_
    - **Detection script file:** _Specify the PowerShell script that checks the device condition_
    - **Remediation script file:** _Specify the PowerShell script that resolves the device condition_
    - **Run this script using the logged-on credentials:** _No_
    - **Enforce script signature check:** _No_
    - **Run script in 64 bit PowerShell:** _No_

3) Proceed to “**Next**” and choose the groups to which you want to assign the script package.
4) Continue to “**Next**” and configure the script schedule.
5) Conclude by selecting “**Create**” to complete the process.

# Contact

If you have any questions or issues with this script, feel free to contact me:

- **Name:** Mickaël CHAVE
- **Email:** mchave3@live.fr
- **GitHub:** [mchave3](https://github.com/mchave3)
- **Linkedin:** [Mickaël CHAVE](https://www.linkedin.com/in/micka%C3%ABl-chave-5301ba15b/)

I appreciate your feedback and am ready to assist with any issues you may encounter.