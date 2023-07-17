<#
    .SYNOPSIS
    A powershell script that will import certificates into Intune

    .PARAMETER AzureEnvironment
    Options are: Public or USGov

    .PARAMETER PlatformType 
    Options are: Windows, iOS, MacOS, AndroidASOP, AndroidAdmin, AndroidEnterprise. Defaults to Windows

    .PARAMETER AssignPolicySet
    Provide the Policy Set or ID to assign the certificates to. 

    .PARAMETER AssignAADGroup
    Provide the Azure AD Group or ID to assign each certificate to. If policy set is specified it will check for that assignment as well. 

    .PARAMETER JSONOnly
    Switch. Only imports JSON files in the JSON folder. Ignores any cer file in the Root, Intermediate, and User folders

    .PARAMETER IncludeExpired
    Switch. Imports certificates that are expired as well. Any JSON that doesn't have the populated description

    .EXAMPLE
    PS> .\Import-IntuneCertificates

    .EXAMPLE
    PS> .\Import-IntuneCertificates -AzureEnvironment USGov

    .EXAMPLE
    PS> .\Import-IntuneCertificates -PlatformType iOS -JSONOnly

    .EXAMPLE
    PS> .\Import-IntuneCertificates -IncludeExpired
    
    .EXAMPLE
    PS> .\Import-IntuneCertificates.ps1 -AzureEnvironment USGov -AssignAADGroup SG-AZ-DeviceGrp-TestDevices -IncludeExpired

#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Public','USGov','USDoD')]
    [string]$AzureEnvironment = 'Public',
    [ValidateSet('Windows','iOS','MacOS','AndroidASOP','AndroidAdmin','AndroidEnterprise')]
    [string]$PlatformType = 'Windows',
    [string]$AssignPolicySet,
    [string]$AssignAADGroup,
    [switch]$JSONOnly,
    [switch]$IncludeExpired
)

#$ErrorActionPreference='Stop'


##*=========================================
##* INTUNE FUNCTIONS
##*=========================================

Function Test-IsGuid{
    param(
        $Guid
    )
    Try{ [System.Guid]::Parse($Guid) -is [Guid] }Catch{ $False}
}

function Get-IntuneConfigurationProfile {
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-IntuneConfigurationProfile
    Returns any device configuration policies configured in Intune
    .NOTES
    https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-deviceconfiguration?view=graph-rest-1.0&viewFallbackFrom=graph-rest-beta
    https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-deviceconfiguration-get?view=graph-rest-1.0&viewFallbackFrom=graph-rest-beta
    #>
    [cmdletbinding(DefaultParameterSetName='All')]
    param(
        [Parameter(Mandatory, ParameterSetName='Name')]
        [string] $DisplayName,

        [Parameter(Mandatory, ParameterSetName='Prefix')]
        [string] $Prefix,

        [Parameter(Mandatory = $false, ParameterSetName='Prefix')]
        [ValidateSet('displayname','@odata.type')]
        [string] $PrefixType ='displayname',

        [Parameter(Mandatory, ParameterSetName='Filter')]
        [string] $Filter
    )

    $apiVersion = 'beta'
    $resource = 'deviceManagement/deviceConfigurations?$expand=assignments'

    try {
        switch($PSCmdlet.ParameterSetName) {
            'Name' {
                $uri = "$($script:GraphEndpoint)/$apiVersion/$resource"
                (Invoke-MgGraphRequest -Method Get -Uri $uri).Value | Where-Object { $_.'displayName' -eq $DisplayName }
            }
            'Prefix' {
                $uri = "$($script:GraphEndpoint)/$apiVersion/$resource"
                (Invoke-MgGraphRequest -Method Get -Uri $uri).Value | Where-Object { ($_.$PrefixType).contains($Prefix) }
            }
            'Filter' {
                $uri = "$($script:GraphEndpoint)/$apiVersion/$resource&`$filter=(isof('$Filter'))"
                (Invoke-MgGraphRequest -Method Get -Uri $uri).Value
            }
            default {
                Write-Verbose ("Invoking Graph: {0}" -f $uri)
                $uri = "$($script:GraphEndpoint)/$apiVersion/$resource"
                (Invoke-MgGraphRequest -Method Get -Uri $uri).Value
            }
        }
    }
    catch {
        Invoke-GraphException -Exception $_.Exception
    }
}


function New-IntuneCertificateConfigurationProfile {
    <#
    .SYNOPSIS
    This function is used to add an device configuration policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device configuration policy
    .EXAMPLE
    New-IntuneCertificateConfigurationProfile -JSON $JSON
    Adds a device configuration policy in Intune
    #>
    [cmdletbinding()]
    param (
        [parameter(Mandatory,ParameterSetName="JSON")]
        [string] $JsonFilePath,

        [parameter(Mandatory,ParameterSetName="Cert")]
        [string] $CertFilePath,

        [parameter(Mandatory,ParameterSetName="Obj")]
        [psobject] $CertObj,

        [ValidateSet('Windows','iOS','MacOS','AndroidASOP','AndroidAdmin','AndroidEnterprise')]
        [string] $Platform = 'Windows'
    )
    
    $apiVersion = 'beta'
    $resource = 'deviceManagement/deviceConfigurations'

    switch($Platform){
        'Windows'           {$odatatype="#microsoft.graph.windows81TrustedRootCertificate"}
        'iOS'               {$odatatype="#microsoft.graph.iosTrustedRootCertificate"}
        'MacOS'             {$odatatype="#microsoft.graph.macOSTrustedRootCertificate"}
        'AndroidASOP'       {$odatatype="#microsoft.graph.aospDeviceOwnerTrustedRootCertificate"}
        'AndroidAdmin'      {$odatatype="#microsoft.graph.androidTrustedRootCertificate"}
        'AndroidEnterprise' {$odatatype="#microsoft.graph.androidTrustedRootCertificate"}
        default             {$odatatype="#microsoft.graph.windows81TrustedRootCertificate"}
    }

    If($PSCmdlet.ParameterSetName -eq "JSON"){
        $JsonObj = Get-Content $JsonFilePath -Raw | ConvertFrom-Json

        #build body from Json excluding assignments
        $jsonbody = $JsonObj |
            Select-Object -Property * -ExcludeProperty *id,*context,version,*assign*,*Link,*Applicability*,lastModifiedDate*,createdDateTime*,*microsoft.graph*,supportsScopeTags,'roleScopeTagIds@odata.type','trustedRootCertificate@odata.type' |
                ConvertTo-Json

                        
        Write-Verbose ('Creating: {0}' -f $JsonObj.DisplayName)
    }

    If($PSCmdlet.ParameterSetName -eq "Cert"){

        $CertInfo = ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertFilePath))
        $CertObj = Get-Item $CertFilePath | Select FullName, 
                        @{n='Type';e={ If($CertInfo.Issuer -eq $CertInfo.Subject){'Root'}Else{'Intermediate'} }},
                        @{n='DisplayName';e={$_.BaseName}},
                        @{n='FileName';e={$_.Name}},
                        @{n='Issuer';e={ $CertInfo.Issuer }},
                        @{n='Expires';e={ $CertInfo.NotAfter }},
                        @{n='Thumbprint';e={ $CertInfo.Thumbprint }}

    }

    If($CertObj){
        
        #build a description based
        If($CertObj.Type -ne 'Root'){
            $description= @"
FileName: $($CertObj.FileName)
Thumbprint: $($CertObj.Thumbprint)
Expires: $($CertObj.Expires)
Issuedby: $($CertObj.Issuer)
"@
            $certStore = "computerCertStoreIntermediate"

        }ElseIf($CertObj.Type -ne 'User'){
            $description= @"
FileName: $($CertObj.FileName)
Thumbprint: $($CertObj.Thumbprint)
Expires: $($CertObj.Expires)
"@
            $certStore = "userCertStoreIntermediate"
        }Else{
            $description= @"
FileName: $($CertObj.FileName)
Thumbprint: $($CertObj.Thumbprint)
Expires: $($CertObj.Expires)
"@
            $certStore = "computerCertStoreRoot"
        }

        $CertInBytes = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes((Get-Content $CertObj.FullName -Raw)))

        $body = @{
            "@odata.type" = $odatatype
            displayName = $CertObj.DisplayName
            description = $description
            trustedRootCertificate = $CertInBytes
            certFileName = $CertObj.FileName
        }
        
        #Add the destination store to the body if windows
        If($Platform -eq 'Windows' ){
            $body += @{
                "destinationStore@odata.type" = "#microsoft.graph.certificateDestinationStore"
                destinationStore = $certStore
            }
        }

        $jsonbody = $body | ConvertTo-Json

        Write-Verbose ('Creating: {0}' -f $CertObj.DisplayName)
    }
    
    try {
        $uri = "$($script:GraphEndpoint)/$apiVersion/$resource"
        
        If($VerbosePreference){
            Invoke-MgGraphRequest -Method Post -Uri $uri -Body $jsonbody -ContentType 'application/json'
        }Else{
            $Response = Invoke-MgGraphRequest -Method Post -Uri $uri -Body $jsonbody -ContentType 'application/json'
        }
        
    }
    catch {
        Invoke-GraphException -Exception $_
    }

    Return $Response
}


function New-IntuneCertificateConfigurationProfileAssignment {
    <#
    .SYNOPSIS
    This function is used to add a device configuration policy assignment using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device configuration policy assignment
    .EXAMPLE
    New-IntuneCertificateConfigurationProfileAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
    Adds a device configuration policy assignment in Intune
    #>
    [cmdletbinding()]
    param (
        [parameter(Mandatory)]
        [guid] $ConfigurationPolicyId,

        [parameter(Mandatory)]
        [guid] $TargetGroupId,

        [parameter(Mandatory)]
        [ValidateSet('AllDevices','AllUsers','AzureADGroup','ExclusionAADGroup')]
        [string] $AssignmentType
    )

    $apiVersion = 'beta'
    $resource = "deviceManagement/deviceConfigurations/$ConfigurationPolicyId/assignments"

    switch($AssignmentType){
        'AllDevices'    {$AssignmentTarget = @{
                            '@odata.type' = "#microsoft.graph.allDevicesAssignmentTarget"
                            deviceAndAppManagementAssignmentFilterId= $null
                            deviceAndAppManagementAssignmentFilterType= "none"
                        }   
        }

        'AllUsers'      {$AssignmentTarget = @{
                            '@odata.type' = "#microsoft.graph.allLicensedUsersAssignmentTarget"
                            deviceAndAppManagementAssignmentFilterId= $null
                            deviceAndAppManagementAssignmentFilterType= "none"
                        }   
        }
        'AzureADGroup'  {$AssignmentTarget = @{
                            '@odata.type' = "#microsoft.graph.groupAssignmentTarget"
                            deviceAndAppManagementAssignmentFilterId= $null
                            deviceAndAppManagementAssignmentFilterType= "none"
                            groupId = $TargetGroupId
                        }   
        }
        'ExclusionAADGroup' {$AssignmentTarget = @{
                                '@odata.type' = "#microsoft.graph.exclusionGroupAssignmentTarget"             
                                deviceAndAppManagementAssignmentFilterId= $null
                                deviceAndAppManagementAssignmentFilterType= "none"
                                groupId = $TargetGroupId
                            }
        }
        default         {$AssignmentTarget = @{
                            '@odata.type' = "#microsoft.graph.groupAssignmentTarget"                
                            deviceAndAppManagementAssignmentFilterId= $null
                            deviceAndAppManagementAssignmentFilterType= "none"
                            groupId = $TargetGroupId
                        }   
        }
    }

    $body = @{
        source = "direct"
        intent = "apply"
        target = $AssignmentTarget
    } | ConvertTo-Json

    try {
        $uri = "$($script:GraphEndpoint)/$apiVersion/$resource"
        Invoke-MgGraphRequest -Method Post -Uri $uri -Body $body -ContentType 'application/json'
    }
    catch {
        Invoke-GraphException -Exception $_.Exception
    }
}

function Get-AADGroup {
    <#
    .SYNOPSIS
    Gets an AAD Group by either it's display name or the internal id
    
    .PARAMETER DisplayName
    The Groups AAD Display Name

    .PARAMETER Id
    The internal module group id
    
    .EXAMPLE
    Get-AADGroup -DisplayName group-MW-users
    In this example the group-MW-users group object is returned

    .EXAMPLE
    Get-AADGroup -Id '4c5b500a-466a-421d-be1d-2ae89f170afa'
    In this example the guid returns the group object in Azure AD
    #>
    [cmdletbinding(DefaultParameterSetName='All')]
    param (
        [Parameter(Mandatory=$false, ParameterSetName='DisplayName')]
        [string] $DisplayName,

        [Parameter(Mandatory=$false, ParameterSetName='Id')]
        [guid] $Id
    )

    Try{
        switch ($PSCmdlet.ParameterSetName)
        {
            'DisplayName' {
                $Return = Get-MgGroup -Filter "DisplayName eq '$DisplayName'" -ErrorAction Stop
            }
            'Id' {
                $Return = Get-MgGroup -Filter "Id eq '$Id'" -ErrorAction Stop
            }
            default{$Return = Get-MgGroup}
        }
    }Catch{
        $Return = $false
    }

    $Return
}

function Invoke-GraphException {
    <#
    .SYNOPSIS
    Helper function to display exception messages and write them to a log file
    .DESCRIPTION
    Helper function to display exception messages and write them to a log file
    .PARAMETER Exception

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [AllowNull()]
        $Exception
    )
    
    #$_.Exception.GetType().FullName
    $ex = $Exception
    If($ex.ErrorDetails.Message){
        #Invoke-GraphException -Exception $_.Exception
        Try{
            $jsonexception = ($ex.ErrorDetails.Message -split '\r?\n')[-1] | ConvertFrom-Json
            Write-Host ("Response content:`n{0}" -f $jsonexception.error.message) -f Red
            Write-Error $jsonexception.error.innerError.message
        }Catch{
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host ("Response content:`n{0}" -f $responseBody) -f Red

            Write-Error ("Request to {0} failed with HTTP Status {1} {2}" -f $Uri,$ex.Response.StatusCode,$ex.Response.StatusDescription)
        }
    }Else{
        Write-Error $ex
    }
    
}
##*=============================================
##* VARIABLES
##*=============================================
#region VARIABLES: Building paths & values
# get paths because PowerShell ISE & other editors have different results
[string]$ResourceRoot = ($PWD.ProviderPath, $PSScriptRoot)[[bool]$PSScriptRoot]


#build paths
$JsonFolder = Join-Path $ResourceRoot -ChildPath 'JSON'
$IntermediateFolder = Join-Path $ResourceRoot -ChildPath 'Intermediate'
$RootFolder = Join-Path $ResourceRoot -ChildPath 'Root'
$UserFolder = Join-Path $ResourceRoot -ChildPath 'User'

# Import Graph modules
Import-Module Microsoft.Graph.Authentication, Microsoft.Graph.Groups
##*=========================================
##* MAIN
##*=========================================
#get the appropiate endpoint for graph

switch($AzureEnvironment){
    'Public' {$script:GraphEndpoint = 'https://graph.microsoft.com';$GraphEnvironment = "Global"}
    'USgov' {$script:GraphEndpoint = 'https://graph.microsoft.us';$GraphEnvironment = "USgov"}
    'USDoD' {$script:GraphEndpoint = 'https://dod-graph.microsoft.us';$GraphEnvironment = "USGovDoD"}
    default {$script:GraphEndpoint = 'https://graph.microsoft.com';$GraphEnvironment = "Global"}
}

#only scope permissions to these
$PermissionScope = @(
    'DeviceManagementConfiguration.ReadWrite.All'
)
#Connect to graph
Write-Host ("`nConnecting to Intune...") -ForegroundColor Cyan
$null = Connect-MgGraph -Environment $GraphEnvironment -Scopes $PermissionScope
#Get-MgContext

#some configuration profiles don't have a store selection
switch($PlatformType){
    'Windows'           {$IgnoreType = $false;$ConfigParam = @{Filter="microsoft.graph.windows81TrustedRootCertificate"}}
    'iOS'               {$IgnoreType = $true;$ConfigParam = @{Filter="microsoft.graph.iosTrustedRootCertificate"}}
    'MacOS'             {$IgnoreType = $true;$ConfigParam = @{Filter="microsoft.graph.macOSTrustedRootCertificate"}}
    'AndroidASOP'       {$IgnoreType = $true;$ConfigParam = @{Filter="microsoft.graph.aospDeviceOwnerTrustedRootCertificate"}}
    'AndroidAdmin'      {$IgnoreType = $true;$ConfigParam = @{Filter="microsoft.graph.windows81TrustedRootCertificate"}}
    'AndroidEnterprise' {$IgnoreType = $true;$ConfigParam = @{Filter="microsoft.graph.androidTrustedRootCertificate"}}
    default             {$IgnoreType = $false;$ConfigParam = @{Filter="microsoft.graph.windows81TrustedRootCertificate"}}
}



Write-Host ("`nCollecting trusted certificates...") -ForegroundColor Cyan -NoNewline
#collect files within folders
$jsonObjList = Get-ChildItem $JsonFolder -Filter *.json | Select FullName, 
                        @{n='Type';e={'Json'}},
                        @{n='DisplayName';e={ (ConvertFrom-Json (Get-Content $_.FullName -Raw)).displayName }},
                        @{n='FileName';e={ ((ConvertFrom-Json (Get-Content $_.FullName -Raw)).description -split '\r?\n')[0].split(':')[1].Trim() }},
                        @{n='Expires';e={ Get-Date ((ConvertFrom-Json (Get-Content $_.FullName -Raw)).description -split '\r?\n')[2].split(':')[1].Trim()}},
                        @{n='Thumbprint';e={ ((ConvertFrom-Json (Get-Content $_.FullName -Raw)).description -split '\r?\n')[1].split(':')[1].Trim() }}

#collect all cer files and provide type 
$intermediateCerObjList = Get-ChildItem $IntermediateFolder -Filter *.cer | Select FullName, 
                        @{n='Type';e={ If($IgnoreType){'Root'}Else{'Intermediate'} }},
                        @{n='DisplayName';e={($_.BaseName + ' [' + $PlatformType + ']')}},
                        @{n='FileName';e={$_.Name}},
                        @{n='Issuer';e={ ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.FullName)).Issuer }},
                        @{n='Expires';e={ ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.FullName)).NotAfter }},
                        @{n='Thumbprint';e={ ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.FullName)).Thumbprint }}

$rootCerObjList = Get-ChildItem $RootFolder -Filter *.cer | Select FullName, 
                        @{n='Type';e={'Root'}},
                        @{n='DisplayName';e={($_.BaseName + ' [' + $PlatformType + ']')}},
                        @{n='FileName';e={$_.Name}},
                        @{n='Issuer';e={ ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.FullName)).Issuer }},
                        @{n='Expires';e={ ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.FullName)).NotAfter }},
                        @{n='Thumbprint';e={ ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.FullName)).Thumbprint }}

$userCerObjList = Get-ChildItem $UserFolder -Filter *.cer | Select FullName, 
                        @{n='Type';e={ If($IgnoreType){'Root'}Else{'User'} }},
                        @{n='DisplayName';e={($_.BaseName + ' [' + $PlatformType + ']')}},
                        @{n='FileName';e={$_.Name}},
                        @{n='Issuer';e={ ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.FullName)).Issuer }},
                        @{n='Expires';e={ ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.FullName)).NotAfter }},
                        @{n='Thumbprint';e={ ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($_.FullName)).Thumbprint }}
#Combine list
$AllCertObjects = $intermediateCerObjList + $rootCerObjList + $userCerObjList
Write-Host ("Found {0}" -f ($jsonObjList.count + $AllCertObjects.count))

#Get collective count to diplay appropiately
If($JSONOnly){
    $CertCount = $jsonObjList.count
}Else{
    $CertCount = ($jsonObjList.count + $AllCertObjects.count)
}

#grab all configurations based on trusted certificate filter
Write-Host ("Collecting trusted certificates profiles...") -ForegroundColor Cyan -NoNewline
$IntuneTrustedCertConfigs = Get-IntuneConfigurationProfile @ConfigParam
Write-Host ("Found {0}" -f $IntuneTrustedCertConfigs.count)

Write-Host ("`nImporting JSON profiles for Trusted certificates...") -ForegroundColor Cyan

$i=0
Foreach($Json in $jsonObjList)
{

    $i++
    Write-Host ("`n[{0}/{1}] Checking for Trusted Certificate profile: {2}" -f $i,$CertCount,$Json.DisplayName)
    
    #correlate profile with file info
    If($ConfigProfile = $IntuneTrustedCertConfigs | Where DisplayName -eq $Json.DisplayName)
    {
        Write-Host ("    |---Trusted Certificate Profile Exists: ") -ForegroundColor Gray -NoNewline
        Write-Host ("{0}" -f $ConfigProfile.Id) -ForegroundColor Green
    
    }Else{
    
        Write-Host ("    |---Trusted Certificate Profile Missing: ") -ForegroundColor Gray -NoNewline
        Write-Host ("{0}" -f $Json.DisplayName) -ForegroundColor Yellow
        
        If( ($Json.Expires -gt (Get-Date)) -or $IncludeExpired)
        {
            Write-Host ("    |---Checking Validity...") -ForegroundColor Gray -NoNewline
            #output color for validity even if expired is included
            If($Json.Expires -gt (Get-Date)){
                Write-Host ("{0}" -f $Json.Expires) -ForegroundColor Green
            }Else{
                Write-Host ("{0}" -f $Json.Expires) -ForegroundColor Yellow
            }

            If($PSCmdlet.ShouldProcess("Performing the operation `"Create Intune Profile`" on target `"$($Json.DisplayName)`"","Create Intune Profile","New-IntuneCertificateConfigurationProfile")){
                Write-Host ("    |---Importing profile: {0}..." -f $Json.DisplayName) -ForegroundColor Gray -NoNewline
                try{
                    $ConfigProfile = New-IntuneCertificateConfigurationProfile -JsonFilePath $Json.FullName
                    Write-Host ("Done" ) -ForegroundColor Green
                }Catch{
                    Write-Host ("Failed: {0}" -f $_) -ForegroundColor Red
                }

                
            }

        }Else{
            
            Write-Host ("    |---Not Imported. Expired: ") -ForegroundColor Gray -NoNewline
            Write-Host ("{0}" -f $Json.Expires) -ForegroundColor Red
        
        }
    }


    If($AssignAADGroup -and $ConfigProfile)
    {
    
        #build assignment object
        $AssignmentTarget = New-Object pscustomobject
        #Check if azure ad group provided in ID; if anot assume its a displayname
        If($AssignAADGroup -match 'AllDevices|AllUsers')
        {
        
            $GroupCatString = 'builtin group'
            $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupType -Value $Matches[0]
            $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupName -Value $Matches[0]
            $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupId -Value (New-Guid)

        }
        ElseIf(Test-IsGuid -Guid $AssignAADGroup )
        {
        
            $GroupCatString = 'group id'
            $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupType -Value 'AzureADGroup'
            If($AADGroupToAssign = Get-AADGroup -Id $AssignAADGroup){
                $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupName -Value $AADGroupToAssign.DisplayName
                $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupId -Value $AADGroupToAssign.Id
            }
        
        }Else{
            
            $GroupCatString = 'group name'
            $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupType -Value 'AzureADGroup'
            If($AADGroupToAssign = Get-AADGroup -DisplayName $AssignAADGroup){
                $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupName -Value $AADGroupToAssign.DisplayName
                $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupId -Value $AADGroupToAssign.Id
            }
        
        }
        
        If($AssignmentTarget.count -gt 0)
        {
            
            If($PSCmdlet.ShouldProcess("Performing the operation `"Assigning Intune Profile`" on target `"$($Json.DisplayName)`"","Assigning Intune Profile","New-IntuneCertificateConfigurationProfileAssignment")){
                Write-Host ("    |---Assigning Group [{0}]..." -f $AssignmentTarget.GroupName) -ForegroundColor Gray -NoNewline
                try{
                    $Assignment = New-IntuneCertificateConfigurationProfileAssignment -ConfigurationPolicyId $ConfigProfile.Id -TargetGroupId $AssignmentTarget.GroupId -AssignmentType $AssignmentTarget.GroupType
                    Write-Host ("Assignment Id: {0}" -f $Assignment.Id) -ForegroundColor Green
                }Catch{
                    Write-Host ("Failed: {0}" -f $_) -ForegroundColor Red
                }
            }

        }Else{

            Write-Host ("    |---Azure AD $GroupCatString not found: ") -ForegroundColor Gray -NoNewline
            Write-Host ("{0}" -f $AssignAADGroup) -ForegroundColor Yellow
            
        }
        $AssignmentTarget = $null

    }
    Start-Sleep 1
}#end json loop


If($JSONOnly -eq $False)
{
    Write-Host ("`nImporting certificate files for Trusted certificates...") -ForegroundColor Cyan
    
    #TEST $CerObj = $AllCertObjects[0]
    Foreach($CerObj in $AllCertObjects)
    {
       
        $i++
        Write-Host ("`n[{0}/{1}] Checking Intune profile: {2}" -f $i,$CertCount,$CerObj.DisplayName)
        If($ConfigProfile = $IntuneTrustedCertConfigs | Where DisplayName -eq $CerObj.DisplayName)
        {
            Write-Host ("    |---Configuration Profile Exists: ") -ForegroundColor Gray -NoNewline
            Write-Host ("{0}" -f $ConfigProfile.Id) -ForegroundColor Green
        
        }Else{

            Write-Host ("    |---Configuration Profile Missing: ") -ForegroundColor Gray -NoNewline
            Write-Host ("{0}" -f $CerObj.DisplayName) -ForegroundColor Yellow

            If( ($CerObj.Expires -gt (Get-Date)) -or $IncludeExpired)
            {
                Write-Host ("    |---Checking Validity...") -ForegroundColor Gray -NoNewline
                #output color for validity even if expired is included
                If($CerObj.Expires -gt (Get-Date)){
                    Write-Host ("{0}" -f $CerObj.Expires) -ForegroundColor Green
                }Else{
                    Write-Host ("{0}" -f $CerObj.Expires) -ForegroundColor Yellow
                }
    
                If($PSCmdlet.ShouldProcess("Performing the operation `"Create Intune Profile`" on target `"$($CerObj.FileName)`"","Create Intune Profile","New-IntuneCertificateConfigurationProfile")){
                    Write-Host ("    |---Creating profile: {0}..." -f $CerObj.DisplayName) -ForegroundColor Gray -NoNewline
                    try{
                        $ConfigProfile = New-IntuneCertificateConfigurationProfile -CertObj $CerObj -Platform $PlatformType
                        Write-Host ("Done" ) -ForegroundColor Green
                    }Catch{
                        Write-Host ("Failed: {0}" -f $_) -ForegroundColor Red
                    }
                }
    
            }Else{

                Write-Host ("    |---Expired: ") -ForegroundColor Gray -NoNewline
                Write-Host ("{0}" -f $CerObj.Expires) -ForegroundColor Red
            }
        }
        
        If($AssignPolicySet){

        }

        If($AssignAADGroup -and $ConfigProfile)
        {

            #build assignment object
            $AssignmentTarget = New-Object pscustomobject
            #Check if azure ad group provided in ID; if anot assume its a displayname
            
            If($AssignAADGroup -match 'AllDevices|AllUsers')
            {

                $GroupCatString = 'builtin group'
                $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupType -Value $Matches[0]
                $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupName -Value $Matches[0]
                $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupId -Value (New-Guid)
            
            }
            ElseIf(Test-IsGuid -Guid $AssignAADGroup )
            {

                $GroupCatString = 'group id'
                $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupType -Value 'AzureADGroup'
                If($AADGroupToAssign = Get-AADGroup -Id $AssignAADGroup){
                    $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupName -Value $AADGroupToAssign.DisplayName
                    $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupId -Value $AADGroupToAssign.Id
                }

            }Else{
                
                $GroupCatString = 'group name'
                $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupType -Value 'AzureADGroup'
                If($AADGroupToAssign = Get-AADGroup -DisplayName $AssignAADGroup){
                    $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupName -Value $AADGroupToAssign.DisplayName
                    $AssignmentTarget | Add-Member -MemberType NoteProperty -Name GroupId -Value $AADGroupToAssign.Id
                }
            }
            
            If($AssignmentTarget.count -gt 0)
            {

                If($PSCmdlet.ShouldProcess("Performing the operation `"Assigning Intune Profile`" on target `"$($CerObj.FileName)`"","Assigning Intune Profile","New-IntuneCertificateConfigurationProfileAssignment")){
                    Write-Host ("    |---Assigning Group [{0}]..." -f $AssignmentTarget.GroupName) -ForegroundColor Gray -NoNewline
                    try{
                        $Assignment = New-IntuneCertificateConfigurationProfileAssignment -ConfigurationPolicyId $ConfigProfile.Id -TargetGroupId $AssignmentTarget.GroupId -AssignmentType $AssignmentTarget.GroupType
                        Write-Host ("Assignment Id: {0}" -f $Assignment.Id) -ForegroundColor Green
                    }Catch{
                        Write-Host ("Failed: {0}" -f $_) -ForegroundColor Red
                    }
                }

            }Else{

                Write-Host ("    |---Azure AD $GroupCatString not found:") -ForegroundColor Gray -NoNewline
                Write-Host ("{0}" -f $AssignAADGroup) -ForegroundColor Yellow

            }
            $AssignmentTarget = $null
        }

        Start-Sleep 1
    }#end folder loop
    
}

#disconnect when done
Write-Host ("`nDisconnecting from Intune...") -ForegroundColor Cyan
Disconnect-MgGraph
