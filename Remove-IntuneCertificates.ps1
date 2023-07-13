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
    Remove-IntuneCertificates

    .EXAMPLE
    Remove-IntuneCertificates -AzureEnvironment USGov

    .EXAMPLE
    Remove-IntuneCertificates -Exclude "RootCA1|RootCA2"
    
    .EXAMPLE
    Remove-IntuneCertificates -PlatformType iOS -JustAssignments

    .EXAMPLE
    Remove-IntuneCertificates -All

#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Public','USGov')]
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


function Remove-IntuneCertificateConfigurationProfileAssignment {

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
Import-Module Microsoft.Graph.Authentication
##*=========================================
##* MAIN
##*=========================================
#get the appropiate endpoint for graph

switch($AzureEnvironment){
    'Public' {$script:GraphEndpoint = 'https://graph.microsoft.com';$GraphEnvironment = "Global"}
    'USgov' {$script:GraphEndpoint = 'https://graph.microsoft.us';$GraphEnvironment = "USgov"}
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

Write-Host ("Found {0}" -f $IntuneTrustedCertConfigs.count)


Write-Host ("`nRemoving profiles for Trusted certificates...") -ForegroundColor Cyan

If($All){
    If($PSCmdlet.ShouldProcess("Performing the operation `"Remove Intune Profile`" on target `"$($IntuneTrustedCertConfigs.count)`"","Remove Intune Profile","Remove-IntuneCertificateConfigurationProfile")){
        Write-Host ("    |---All {0} profiles being removed..." -f $IntuneTrustedCertConfigs.count)
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
    <#
    $TrustedCertProfileDetails = $IntuneTrustedCertConfigs | Select Id, DisplayName,
        @{n='FileName';e={ $_.certFileName }},
        @{n='Expires';e={ Get-Date (($_.description -split '\r?\n')[2] -split ':',2)[1].Trim()}},
        @{n='Thumbprint';e={ ($_.description -split '\r?\n')[1].split(':')[1].Trim() }},
        @{n='Content';e={ [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($_.trustedRootCertificate)) }}
    #>

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
        $ExpiredCerts = $TrustedCertProfileDetails | Where-Object {($_.Expires -lt (Get-Date)) -and ($_.displayName -notmatch $Exclude)}
    }Else{
        $ExpiredCerts = $TrustedCertProfileDetails | Where-Object {($_.Expires -lt (Get-Date))}
    }
    
    Write-Host ("    |---Removing {0} profiles with expired certificates..." -f $ExpiredCerts.count) -NoNewline
    
    If($ExpiredCerts.count -gt 0){
        If($PSCmdlet.ShouldProcess("Performing the operation `"Remove Intune Profile`" on targets `"$($ExpiredCerts.count)`"","Remove Intune Profile","Remove-IntuneCertificateConfigurationProfile")){
            Try{
                $ExpiredCerts.Id | Remove-IntuneCertificateConfigurationProfile
                Write-Host ("Done" ) -ForegroundColor Green
            }Catch{
                Write-Host ("Failed: {0}" -f $_) -ForegroundColor Red
            }
        }
    }Else{
        Write-Host ("No Expired certs found!") -ForegroundColor Green
    }
}