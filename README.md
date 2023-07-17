# Intune Certificate Manager Scripts
A couple of PowerShell scripts to manage multiple certificates within Intune. 

## Why use this?
If you have ever loaded a chain of certificates for large organizations, you will find it very time consuming importing every root and intermediate certs into Intune. 
The next problem is there is no way of knowing which certificates is expired and is no longer needed. 

I developed this to resolve both of those issues.

## What it does

There are two scripts:
- **Import-IntuneCertificates.ps1** - This will import 3 types of certificates (root, intermediate, and user) into their appropriate certificate store. The script will parse cer files within the folders plus JSON files exported from other Intune environment. 
> NOTE. There are folders this script will look at (but are not in repo). Folders: Root, Intermediate, User and JSON. If you want to import scripts, create these folders and place the respective cert your importing into them

- **Remove-IntuneCertificates.ps1** - This will remove certificates based on expiration. It will export the cert and view it to determine if it expired. 



## Screenshots

![cert](.images/cert_description.png)

![import](.images/import_runexample.png)

![remove](.images/remove_runexample.png)

## Supported platforms

- Windows
- iOS
- MacOS
- Android ASOP
- Android Admin
- Android Enterprise

## Supported Azure Environments

- Public (Commercial and GCC)
- USGov (GCCH/IL4)

## Not Tested but available

- USGovDoD (GCCH/IL5)

## Import Options

- **AzureEnvironment** - Options are: _Public, USGov_. USDod is an option but not tested.  Defaults to _Public_
- **PlatformType** - Options are: _Windows, iOS, MacOS, AndroidASOP, AndroidAdmin, AndroidEnterprise_. Defaults to _Windows_
- **AssignPolicySet** - NOT READY. Provide the Policy Set or ID to assign the certificates to. 
- **AssignAADGroup** - Provide the Azure AD Group or ID to assign each certificate to. 
- **JSONOnly** - Switch. Only imports JSON files in the JSON folder. Ignores any cer file in the Root, Intermediate, and User folders
- **IncludeExpired** - Switch. Creates certificates profile that are expired as well.
> Any JSON that doesn't have the populated description with _Expires:_ will import

## Remove Options

- **AzureEnvironment** - Options are: _Public, USGov_. USDod is an option but not tested. Defaults to _Public_
- **PlatformType** - Options are: _Windows, iOS, MacOS, AndroidASOP, AndroidAdmin, AndroidEnterprise_. Defaults to _Windows_
- **Exclude** - Specify what certs to exclude. String can include regex pipe for multiple (eg. RootCA1|RootCA2)
- **JustAssignments** - Switch. Only removes assignment from configuration profile
- **All** - Switch. Removes all certificate profiles based on platform


# Typical examples to manage cert

Create only _non-expired_ certificate profiles and assign to all **Windows** devices
```powershell
PS> .\Import-IntuneCertificates.ps1 -AssignAADGroup 'AllDevices'
```

Create only _non-expired_ certificate profiles and assign to all **iOS** devices
```powershell
PS> .\Import-IntuneCertificates.ps1 -PlatformType iOS -AssignAADGroup 'AllDevices'
```

Create only _non-expired_ certificate profiles and assign to Azure AD group
```powershell
PS> .\Import-IntuneCertificates.ps1 -AssignAADGroup 'SG-AZ-DeviceGrp-TestDevices'
```

Remove _expired_ certificate profile **assignments** only
```powershell
PS> .\Remove-IntuneCertificates.ps1 -JustAssignments
```

Remove _expired_ certificate profiles
```powershell
PS> .\Remove-IntuneCertificates.ps1
```


## Additional options:
 
 - the **-WhatIf** command is supported and allows for testing prior to import or removal. 
 - the **-Verbose** is also supported and will output additional details...however the output may not be cleanly displayed. 

# Notes/Issues

- Currently only group assignments are working. Policy Set assigning will be coming shortly
- Any JSON that doesn't have the populated description with _Expires:_ will import
- Script do not detect filtered assignments or remove filters from assignments 

# DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  **THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE**.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys’ fees, that arise or result
from the use or distribution of the Sample Code.

This posting is provided "AS IS" with no warranties, and confers no rights. Use
of included script samples are subject to the terms specified
at https://www.microsoft.com/en-us/legal/copyright.
