<#
    .SYNOPSIS
    A powershell script that will remove certificates from Intune

    .PARAMETER AzureEnvironment
    Options are: Public or USGov. Defaults to Public

    .PARAMETER PlatformType 
    Options are: Windows, iOS, MacOS, AndroidASOP, AndroidAdmin, AndroidEnterprise. Defaults to 'Windows'

    .PARAMETER Exclude
    Specify what certs to exclude. String can include regex pipe for multiple (eg. RootCA1|RootCA2)

    .PARAMETER JustAssignments
     Switch. Only removes assignment from target

    .PARAMETER All
    Switch. Removes all certificates based on platform
    
    .EXAMPLE
    PS> .\Remove-IntuneCertificates

    .EXAMPLE
    PS> .\Remove-IntuneCertificates -AzureEnvironment USGov

    .EXAMPLE
    PS> .\Remove-IntuneCertificates -Exclude "RootCA1|RootCA2"
    
    .EXAMPLE
    PS> .\Remove-IntuneCertificates -PlatformType iOS -JustAssignments

    .EXAMPLE
    PS> .\Remove-IntuneCertificates -All

    .EXAMPLE
    PS> .\Remove-IntuneCertificates -All -WhatIf

#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Public','USGov','USDoD')]
    [string]$AzureEnvironment = 'Public',
    [ValidateSet('Windows','iOS','MacOS','AndroidASOP','AndroidAdmin','AndroidEnterprise')]
    [string]$PlatformType,
    [string]$Exclude,
    [switch]$JustAssignments,
    [switch]$All
)

#$ErrorActionPreference='Stop'


##*=========================================
##* INTUNE FUNCTIONS
##*=========================================

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

function Remove-IntuneCertificateConfigurationProfile {
    [cmdletbinding(DefaultParameterSetName='Id')]
    param(
        [Parameter(Mandatory, ParameterSetName='Name')]
        [string] $DisplayName,

        [Parameter(Mandatory, ParameterSetName='Id',ValueFromPipeline,ValueFromPipelineByPropertyName)]
        [string] $Id
    )
    Begin{
        $apiVersion = 'beta'
    }
    Process{
        
        switch($PSCmdlet.ParameterSetName) {
            'Name' {
                Write-Verbose ("Deleting configuration profile name: {0}" -f $DisplayName)
                $deviceConfiguration = Get-IntuneConfigurationProfile -DisplayName $DisplayName
                $resource = "deviceManagement/deviceConfigurations/$($deviceConfiguration.Id)"
            }
            'Id' {
                Write-Verbose ("Deleting configuration profile id: {0}" -f $Id)
                $resource = "deviceManagement/deviceConfigurations/$Id"
            }
        }

        try {
            $uri = "$($script:GraphEndpoint)/$apiVersion/$resource"
            Invoke-MgGraphRequest -Method Delete -Uri $uri
        }
        catch {
            Invoke-GraphException -Exception $_.Exception
        }
    }
    End{}
}


function Remove-IntuneConfigurationProfileAssignment {
    <#
    .SYNOPSIS
    This function is used to remove an assignement from an Intune Configuration profile
    .DESCRIPTION
    The function connects to the Graph API Interface and remove a device configuration policy assignment
    .EXAMPLE
    Remove-IntuneConfigurationProfileAssignment -ConfigurationId $AutoPilotProfileId -AssignmentId $AssignmentId

    .NOTES
    Requires scope:
        DeviceManagementServiceConfig.ReadWrite.All

    #>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [string] $ConfigurationId,

        [Parameter(Mandatory)]
        [string] $AssignmentId
    )

    $apiVersion = 'beta'
    $resource = "deviceManagement/deviceConfigurations/$ConfigurationId/assignments/$AssignmentId"
    
    try {
        $uri = "$($script:GraphEndpoint)/$apiVersion/$resource"
        Invoke-MgGraphRequest -Method Delete -Uri $uri
    }
    catch {
        New-Exception -Exception $_.Exception
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

    #pseudo-group identifiers
    $AADPseudoGroup = @{
        AllUsers   = "acacacac-9df4-4c7d-9d50-4ef0226f57a9"
        AllDevices = "adadadad-808e-44e2-905a-0b7873a8a531"
    }

    Try{
        switch ($PSCmdlet.ParameterSetName)
        {
            'DisplayName' {
                If($DisplayName -match ($AADPseudoGroup.Keys -join '|')){
                    $Group = "" | Select Id, DisplayName
                    $Group.DisplayName = $DisplayName
                    $Group.Id = $AADPseudoGroup[$DisplayName]
                    $Return = $Group
                }Else{
                    $Return = Get-MgGroup -Filter "DisplayName eq '$DisplayName'" -ErrorAction Stop
                }
                
            }
            'Id' {
                If($Id -match ($AADPseudoGroup.Values -join '|')){
                    $Group = "" | Select Id, DisplayName
                    $Group.DisplayName = ($AADPseudoGroup.Keys | Where-Object {$AADPseudoGroup["$_"] -eq $Id})
                    $Group.Id = $Id
                    $Return = $Group
                }Else{
                    $Return = Get-MgGroup -Filter "Id eq '$Id'" -ErrorAction Stop
                }
                
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

# Import Graph modules
Import-Module Microsoft.Graph.Authentication
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
    'Windows'           {$ConfigParam = @{Filter="microsoft.graph.windows81TrustedRootCertificate"}}
    'iOS'               {$ConfigParam = @{Filter="microsoft.graph.iosTrustedRootCertificate"}}
    'MacOS'             {$ConfigParam = @{Filter="microsoft.graph.macOSTrustedRootCertificate"}}
    'AndroidASOP'       {$ConfigParam = @{Filter="microsoft.graph.aospDeviceOwnerTrustedRootCertificate"}}
    'AndroidAdmin'      {$ConfigParam = @{Filter="microsoft.graph.windows81TrustedRootCertificate"}}
    'AndroidEnterprise' {$ConfigParam = @{Filter="microsoft.graph.androidTrustedRootCertificate"}}
    default             {$ConfigParam = @{Filter="microsoft.graph.windows81TrustedRootCertificate"}}
}

#grab all configurations based on trusted certificate filter
Write-Host ("Collecting trusted certificates profiles...") -ForegroundColor Cyan -NoNewline
If($null -eq $PlatformType){
    $IntuneTrustedCertConfigs = Get-IntuneConfigurationProfile
}Else{
    $IntuneTrustedCertConfigs = Get-IntuneConfigurationProfile @ConfigParam
}

If($IntuneTrustedCertConfigs.count -eq 0){
    Write-Host ("None found to remove..." -f $IntuneTrustedCertConfigs.count) -ForegroundColor Green
    Break    
}Else{
    Write-Host ("Found {0}" -f $IntuneTrustedCertConfigs.count)
}

Write-Host ("    |---Collecting details for each Trusted certificates profile...") -ForegroundColor Gray -NoNewline
$TrustedCertProfileDetails = @()
Foreach($Profile in $IntuneTrustedCertConfigs)
{
    #Determine which ones to remove (expired or all)
    If($All)
    {
        $TrustedCertProfileDetails += $Profile | Select Id, displayName,
                                        @{n='FileName';e={ $_.certFileName }},
                                        @{n='Assignments';e={ $_.assignments }}
    }Else{

        $CertFilePath = "$env:TEMP\$($Profile.certFileName -replace '\W+','')"

        #convert base64 to string then to file
        $CertContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Profile.trustedRootCertificate))
        $CertContent | Out-File $CertFilePath -Force -Encoding ascii -WhatIf:$false
        
        #extract certificate infomation from file
        $CertInfo = ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertFilePath))
        #Write-Host ("Thumbprint is: {0}" -f $CertInfo.Thumbprint)
        #Write-Host ("Expire date is: {0}" -f $CertInfo.Expires)
        
        $TrustedCertProfileDetails += $Profile | Select Id, displayName,
                                        @{n='FileName';e={ $_.certFileName }},
                                        @{n='Expires';e={ (Get-Date $CertInfo.NotAfter) }},
                                        @{n='Thumbprint';e={ $CertInfo.Thumbprint }},
                                        @{n='Assignments';e={ $_.assignments }}

        <# pull from profile description
        $TrustedCertProfileDetails = $IntuneTrustedCertConfigs | Select Id, DisplayName,
            @{n='FileName';e={ $_.certFileName }},
            @{n='Expires';e={ Get-Date (($_.description -split '\r?\n')[2] -split ':',2)[1].Trim()}},
            @{n='Thumbprint';e={ ($_.description -split '\r?\n')[1].split(':')[1].Trim() }},
            @{n='Content';e={ [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($_.trustedRootCertificate)) }}
        #>
    }

}
Write-Host ("Done") -ForegroundColor Green

#Dyanmicaly build filter to look at expired and dates
$filterArray = @()
If(!$All){ $filterArray += {$_.Expires -lt (Get-Date)} }
If($Exclude){ $filterArray += {$_.displayName -notmatch $Exclude} }Else{$filterArray += {$_.displayName -like '*'}}
$filter = [scriptblock]::create(($filterArray -join ' -and '))
<#
If($Exclude){
    $CertsToRemove = $TrustedCertProfileDetails | Where-Object {($_.Expires -lt (Get-Date)) -and ($_.displayName -notmatch $Exclude)}
}Else{
    $CertsToRemove = $TrustedCertProfileDetails | Where-Object {($_.Expires -lt (Get-Date))}
}
#>
#TEST $CertsToRemove = $TrustedCertProfileDetails | Where-Object Assignments -ne $null
$CertsToRemove = $TrustedCertProfileDetails | Where-Object -FilterScript $filter

If($CertsToRemove.count -gt 0){
    Write-Host ("`nRemoving {0} identified trusted certificate profiles..." -f $CertsToRemove.count) -ForegroundColor Cyan
    $i=0

    #TEST $Cert = $CertsToRemove[0]
    #TEST $Cert = $CertsToRemove[1]
    Foreach($Cert in $CertsToRemove){
        $i++

        #Determine to remove the assignments or profile itself
        If($JustAssignments){
            
            Write-Host ("`n[{0}/{1}] Collecting assignment(s) from profile: " -f $i,$CertsToRemove.count) -NoNewline
            Write-Host ("{0}" -f $Cert.displayName) -ForegroundColor Green
            If($Cert.Assignments.count -gt 0){
                Foreach($Assignment in $Cert.Assignments)
                {
                    Switch($Assignment.target.'@odata.type'){
                        "#microsoft.graph.allDevicesAssignmentTarget"       {$GroupDetails = Get-AADGroup -Id "adadadad-808e-44e2-905a-0b7873a8a531"}
                        "#microsoft.graph.allLicensedUsersAssignmentTarget" {$GroupDetails = Get-AADGroup -Id "acacacac-9df4-4c7d-9d50-4ef0226f57a9"}
                        "#microsoft.graph.groupAssignmentTarget"            {$GroupDetails = Get-AADGroup -Id $Assignment.target.groupId}
                        "#microsoft.graph.exclusionGroupAssignmentTarget"   {$GroupDetails = Get-AADGroup -Id $Assignment.target.groupId}
                    }
                    
                    If($PSCmdlet.ShouldProcess("Performing the operation `"Remove Intune Profile Assignment`" on targets `"$($Cert.displayName)`"","Remove Intune Profile Assignment","Remove-IntuneConfigurationProfileAssignment")){
                        Write-Host ("    |---Removing Azure AD Group: ") -ForegroundColor Gray -NoNewline
                        Write-Host ("{0}..." -f $GroupDetails.DisplayName) -ForegroundColor Yellow
                        Try{
                            $null = Remove-IntuneConfigurationProfileAssignment -ConfigurationId $Cert.Id -AssignmentId $Assignment.Id
                            Write-Host ("        |---Removed Assignment Id: " -f $Assignment.Id) -ForegroundColor White
                            Write-Host ("{0}" -f $Assignment.Id) -ForegroundColor Green
                        }Catch{
                            Write-Host ("Failed: {0}" -f $_) -ForegroundColor Red
                        }
                    }
    
                }
            }Else{
                Write-Host ("    |---No assignments not found for: ") -ForegroundColor Gray -NoNewline
                Write-Host ("{0}" -f $Cert.displayName) -ForegroundColor Yellow
            }
        }
        Else{
            
            If($PSCmdlet.ShouldProcess("Performing the operation `"Remove Intune Profile`" on targets `"$($Cert.displayName)`"","Remove Intune Profile","Remove-IntuneCertificateConfigurationProfile")){
                Write-Host ("    |---[{0}/{1}] Removing profile: {2}" -f $i,$CertsToRemove.count,$Cert.displayName)
                Try{
                    Remove-IntuneCertificateConfigurationProfile -DisplayName $Cert.displayName
                    Write-Host ("Done" ) -ForegroundColor Green
                }Catch{
                    Write-Host ("Failed: {0}" -f $_) -ForegroundColor Red
                }
            }

        }
        
    }
}Else{
    Write-Host ("    |---No certificate profiles to remove!") -ForegroundColor Green
}


<#
If($All)
{
    
    

    If($PSCmdlet.ShouldProcess("Performing the operation `"Remove Intune Profile`" on target `"$($IntuneTrustedCertConfigs.count)`"","Remove Intune Profile","Remove-IntuneCertificateConfigurationProfile")){
        Write-Host ("    |---All {0} trusted certificate profiles will be removed..." -f $IntuneTrustedCertConfigs.count) -NoNewline
        Try{
            $IntuneTrustedCertConfigs.Id | Remove-IntuneCertificateConfigurationProfile
            Write-Host ("Done" ) -ForegroundColor Green
        }Catch{
            Write-Host ("Failed: {0}" -f $_) -ForegroundColor Red
        }
    }

}Else{

    Write-Host ("    |---Determining thumbprint and validity for certificates...") -NoNewline
    #analyze each profile

    #TEST $Cert = $TrustedCertProfileDetails[0]
    #TEST $Cert = $TrustedCertProfileDetails[1]
    $TrustedCertProfileDetails = @()
    Foreach($Cert in $IntuneTrustedCertConfigs){
        $CertFilePath = "$env:TEMP\$($Cert.certFileName -replace '\W+','')"

        #convert base64 to string then to file
        $CertContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Cert.trustedRootCertificate))
        $CertContent | Out-File $CertFilePath -Force -Encoding ascii -WhatIf:$false
        
        #extract certificate infomation from file
        $CertInfo = ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertFilePath))
        #Write-Host ("Thumbprint is: {0}" -f $CertInfo.Thumbprint)
        #Write-Host ("Expire date is: {0}" -f $CertInfo.Expires)
        
        $TrustedCertProfileDetails += $Cert | Select Id, displayName,
                                        @{n='FileName';e={ $_.certFileName }},
                                        @{n='Expires';e={ (Get-Date $CertInfo.NotAfter) }},
                                        @{n='Thumbprint';e={ $CertInfo.Thumbprint }}
    }
    Write-Host ("Done") -ForegroundColor Green

    If($Exclude){
        $CertsToRemove = $TrustedCertProfileDetails | Where-Object {($_.Expires -lt (Get-Date)) -and ($_.displayName -notmatch $Exclude)}
    }Else{
        $CertsToRemove = $TrustedCertProfileDetails | Where-Object {($_.Expires -lt (Get-Date))}
    }
    
    Write-Host ("    |---Removing {0} trusted certificate profiles with expired certificates..." -f $CertsToRemove.count) -NoNewline
    
    If($CertsToRemove.count -gt 0){
        If($PSCmdlet.ShouldProcess("Performing the operation `"Remove Intune Profile`" on targets `"$($CertsToRemove.count)`"","Remove Intune Profile","Remove-IntuneCertificateConfigurationProfile")){
            Try{
                $CertsToRemove.Id | Remove-IntuneCertificateConfigurationProfile
                Write-Host ("Done" ) -ForegroundColor Green
            }Catch{
                Write-Host ("Failed: {0}" -f $_) -ForegroundColor Red
            }
        }
    }Else{
        Write-Host ("No Expired certs found!") -ForegroundColor Green
    }
}
#>

#disconnect when done
Write-Host ("`nDisconnecting from Intune...") -ForegroundColor Cyan
Disconnect-MgGraph