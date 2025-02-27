#Script to rename content of Intune template files to match customer environment

#Functions

# Import Modules and connect to Azure AD and MSGraph

Function Configure-Terminal {
$Modules = "AzureAD","MSGraphFunctions","IntuneBackupAndRestore"

write-host
#Configure Import MSGraph and IntuneBackup and Restore functions
write-host "Configure Import MSGraph and IntuneBackup and Restore functions" -ForegroundColor Green
Write-host

# Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

    Foreach ($Module in $Modules) {
        try {
            if (Get-Module -ListAvailable -Name $Module) { 
                Write-host "The module $Module is installed, continuing..."
            } 
            else {
                Write-host "The module $Module being installed..."
                Install-Module $Module -Scope CurrentUser -force
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occured while preparing the migration terminal: $($_.Exception.Message)";
        }
    }
}

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $User
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | select -Unique

            }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "https://graph.microsoft.com"

$authority = "https://login.microsoftonline.com/$Tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}

####################################################

Function Get-DeviceConfigurationPolicyAssignment(){

<#
.SYNOPSIS
This function is used to get device configuration policy assignment from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a device configuration policy assignment
.EXAMPLE
Get-DeviceConfigurationPolicyAssignment $id guid
Returns any device configuration policy assignment configured in Intune
.NOTES
NAME: Get-DeviceConfigurationPolicyAssignment
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true,HelpMessage="Enter id (guid) for the Device Configuration Policy you want to check assignment")]
    $id
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"

    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/groupAssignments"
    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Get-ADMXPolicy(){

<#
.SYNOPSIS
This function is used to get ADministrative Templates from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets ADministrative Templates
.EXAMPLE
Get-ADMXPolicy 

Returns any device configuration policy assignment configured in Intune
.NOTES
NAME: Get-ADMXPolicy
#>

[cmdletbinding()]

 
$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/groupPolicyConfigurations"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
#       $ADMX = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
       (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
#$ADMT = Invoke-MSGraphRequest -HttpMethod GET -Url $uri
#$AllADMT = $ADMT.value
        
}
####################################################

Function Get-DeviceManagementIntent(){

<#
.SYNOPSIS
This function is used to get Device Management Intents from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets Device Management Intents
.EXAMPLE
Get-DeviceManagementIntent

Returns any device configuration policy assignment configured in Intune
.NOTES
NAME: Get-DeviceManagementIntent
#>

[cmdletbinding()]

 
$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/intents"

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
       (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
#$ADMT = Invoke-MSGraphRequest -HttpMethod GET -Url $uri
#$AllADMT = $ADMT.value
        
}
####################################################

Function Add-DeviceConfigurationPolicyAssignment(){

    <#
    .SYNOPSIS
    This function is used to add a device configuration policy assignment using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device configuration policy assignment
    .EXAMPLE
    Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId -AssignmentType Included
    Adds a device configuration policy assignment in Intune
    .NOTES
    NAME: Add-DeviceConfigurationPolicyAssignment
    #>
    
    [cmdletbinding()]
    
    param
    (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $ConfigurationPolicyId,
    
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $TargetGroupId,
    
        [parameter(Mandatory=$true)]
        [ValidateSet("Included","Excluded")]
        [ValidateNotNullOrEmpty()]
        [string]$AssignmentType
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceConfigurations/$ConfigurationPolicyId/assign"
 
        try {
    
            if(!$ConfigurationPolicyId){
    
                write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
                break
    
            }
    
            if(!$TargetGroupId){
    
                write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
                break
    
            }
    
            # Checking if there are Assignments already configured in the Policy
            $DCPA = Get-DeviceConfigurationPolicyAssignment -id $ConfigurationPolicyId
    
            $TargetGroups = @()
    
            if(@($DCPA).count -ge 1){
                
                if($DCPA.targetGroupId -contains $TargetGroupId){
    
                Write-Host "Group with Id '$TargetGroupId' already assigned to Policy..." -ForegroundColor Red
                Write-Host
                break
    
                }
    
                # Looping through previously configured assignements
    
                $DCPA | foreach {
    
                $TargetGroup = New-Object -TypeName psobject
         
                    if($_.excludeGroup -eq $true){
    
                        $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
                    }
         
                    else {
         
                        $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
                    }
    
                $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $_.targetGroupId
    
                $Target = New-Object -TypeName psobject
                $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
    
                $TargetGroups += $Target
    
                }
    
                # Adding new group to psobject
                $TargetGroup = New-Object -TypeName psobject
    
                    if($AssignmentType -eq "Excluded"){
    
                        $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
                    }
         
                    elseif($AssignmentType -eq "Included") {
         
                        $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
                    }
         
                $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
    
                $Target = New-Object -TypeName psobject
                $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
    
                $TargetGroups += $Target
    
            }
    
            else {
    
                # No assignments configured creating new JSON object of group assigned
                
                $TargetGroup = New-Object -TypeName psobject
    
                    if($AssignmentType -eq "Excluded"){
    
                        $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
                    }
         
                    elseif($AssignmentType -eq "Included") {
         
                        $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
                    }
         
                $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
    
                $Target = New-Object -TypeName psobject
                $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
    
                $TargetGroups = $Target
    
            }
    
        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
    
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
    
        $JSON = $Output | ConvertTo-Json -Depth 3
    
        # POST to Graph Service
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
    
        }
        
        catch
        
        {
    

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
          }
     }
    

####################################################

Function Remove-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to remove a device configuration policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and removes a device configuration policies
.EXAMPLE
Remove-DeviceConfigurationPolicy -id $id
Removes a device configuration policies configured in Intune
.NOTES
NAME: Remove-DeviceConfigurationPolicy
#>

[cmdletbinding()]

param
(
    $id
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"

    try {

        if($id -eq "" -or $id -eq $null){

        write-host "No id specified for device configuration, can't remove configuration..." -f Red
        write-host "Please specify id for device configuration..." -f Red
        break

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete

        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Remove-ADMXTemplateConfiguration(){

<#
.SYNOPSIS
This function is used to remove an administrative tempalte from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and removes an administrative template
.EXAMPLE
Remove-ADMXTemplateConfiguration -id $id
Removes an administrative template policy configured in Intune
.NOTES
NAME: Remove-ADMXTemplateConfiguration
#>

[cmdletbinding()]

param
(
    $id
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/groupPolicyConfigurations"

    try {

        if($id -eq "" -or $id -eq $null){

        write-host "No id specified for device configuration, can't remove configuration..." -f Red
        write-host "Please specify id for device configuration..." -f Red
        break

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete

        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Remove-deviceManagementintents(){

<#
.SYNOPSIS
This function is used to remove a device configuration policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and removes a device configuration policies
.EXAMPLE
Remove-deviceManagementintents -id $id
Removes a device configuration policies configured in Intune
.NOTES
NAME: Remove-deviceManagementintents
#>

[cmdletbinding()]

param
(
    $id
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/intents"

    try {

        if($id -eq "" -or $id -eq $null){

        write-host "No id specified for device management intent, can't remove configuration..." -f Red
        write-host "Please specify id for device management intent..." -f Red
        break

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Delete

        }

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Set-DeviceConfigAssignments(){

param
(
    [switch]$remove
)

$TargetGroup = Get-Groups | Get-MSGraphAllPages | Where-Object displayName -eq $_.Group
$TargetGroupID = $TargetGroup.id

if($TargetGroupId -eq $null -or $TargetGroupId -eq ""){

    Write-Host "AAD Group - '$_.Group' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host

    }

if ($_.Type -eq 'DeviceConfig') {

$deviceConfigurationObject = Get-DeviceManagement_DeviceConfigurations | Get-MSGraphAllPages | Where-Object displayName -eq $_.Policy
$ConfigurationPolicyId = $deviceConfigurationObject.id
$PolicyName = $_.Policy
Write-host "Number of $PolicyName policies found: $($deviceConfigurationObject.DisplayName.Count)" -ForegroundColor cyan

Foreach ($config in $deviceConfigurationObject) {
Write-host $Config.displayName "   "$Config.id -ForegroundColor Yellow

if ($remove.isPresent){
Remove-DeviceConfigurationPolicy -id $config.id
Write-Host $config.id " Removed" -ForegroundColor Cyan
}
                                              }

if($ConfigurationPolicyId -eq $null -or $ConfigurationPolicyId -eq ""){

    Write-Host "Configuration Policy ID for $PolicyName doesn't exist" -ForegroundColor Red
    Write-Host

    }
}

if ($_.Type -eq 'ADMX') {

$deviceConfigurationObject = Get-ADMXPolicy | Get-MSGraphAllPages | Where-Object displayName -eq $_.Policy
$ConfigurationPolicyId = $deviceConfigurationObject.id
$PolicyName = $_.Policy
Write-host "Number of $PolicyName policies found: $($deviceConfigurationObject.DisplayName.Count)" -ForegroundColor cyan

Foreach ($config in $deviceConfigurationObject) {
Write-host $Config.displayName "   "$Config.id -ForegroundColor Yellow

if ($remove.isPresent){ 
Remove-ADMXTemplateConfiguration -id $config.id
Write-Host $config.id " Removed" -ForegroundColor Cyan
                      }
                                                }

                         }
                         

if($ConfigurationPolicyId -eq $null -or $ConfigurationPolicyId -eq ""){

    Write-Host "Configuration Policy ID for $PolicyName doesn't exist" -ForegroundColor Red
    Write-Host

    }

if ($_.Type -eq 'Intent') {

$deviceConfigurationObject = Get-DeviceManagementIntent | Get-MSGraphAllPages | Where-Object displayName -eq $_.Policy
$ConfigurationPolicyId = $deviceConfigurationObject.id
$PolicyName = $_.Policy
Write-host "Number of $PolicyName policies found: $($deviceConfigurationObject.DisplayName.Count)" -ForegroundColor cyan

Foreach ($config in $deviceConfigurationObject) {
Write-host $Config.displayName "   "$Config.id -ForegroundColor Yellow

if ($remove.isPresent){
Remove-DeviceManagementIntents -id $config.id
Write-Host $config.id " Removed" -ForegroundColor Cyan
                      }

                                              }
                         }

if($ConfigurationPolicyId -eq $null -or $ConfigurationPolicyId -eq ""){

    Write-Host "Configuration Policy ID for $PolicyName doesn't exist" -ForegroundColor Red
    Write-Host

    }

if ($_.Type -eq 'Compliance') {

$deviceConfigurationObject = Get-DeviceManagement_DeviceCompliancePolicies | Get-MSGraphAllPages | Where-Object displayName -eq $_.Policy
$ConfigurationPolicyId = $deviceConfigurationObject.id
$PolicyName = $_.Policy
Write-host "Number of $PolicyName policies found: $($deviceConfigurationObject.DisplayName.Count)" -ForegroundColor cyan

Foreach ($config in $deviceConfigurationObject) {
Write-host $Config.displayName "   "$Config.id -ForegroundColor Yellow

if ($remove.isPresent){
Remove-IntuneDeviceCompliancePolicy -id $config.id
Write-Host $config.id " Removed" -ForegroundColor Cyan
                      }
                                              }
                         }

if($ConfigurationPolicyId -eq $null -or $ConfigurationPolicyId -eq ""){

    Write-Host "Configuration Policy ID for $PolicyName doesn't exist" -ForegroundColor Red
    Write-Host

    }


#Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId -AssignmentType Included
Clear-Variable -Name "TargetGroupID"
}

################################################################

#Modify the below variables to match the customer requirements

$RemoveExisting = "Yes"
$PolicyNamePrefix = "ADJ_"
$GroupNamePrefix = ""
$HomepageURL = "https://www.bbc.co.uk"
$TenantAuthDomain = "contoso.onmicrosoft.com"
$EdgeTabPageURL = "https://www.youtube.com"
$EdgeHomePageURL = "https://www.microsoft.com"
$DefenderSecurityCenterSupportName = "Contoso - IT Support"
$ChromeHomePageLocation = "https://www.bbc.co.uk"
$ChromeRestoreOnStartupURL = "https://www.microsoft.com"

#Fixed Variables, DO NOT change
$JSON1 = ".\Device Configurations\UK_Windows_DR_WithM365Apps_StartLayout.json"
$JSON2 = ".\Device Configurations\UK_Windows_DR_WithO2016_StartLayout.json"
$JSON3 = ".\Administrative Templates\UK_Windows_AdminTemplates.json"
$JSON4 = ".\Device Configurations\UK_Windows_Settings_Chrome.json"
$JSON5 = ".\Device Configurations\UK_Windows_EPProtection.json"



#region Authentication



Configure-Terminal
Connect-AzureAD -AccountID $User
Connect-MSGraph

write-host "Configure Azure AD module and Autentication Token" -ForegroundColor Green
Write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

####################################################


<##################Start Main Script##################>

# Create a log folder
if (-not (Test-Path "c:\temp\UltimaIntuneTemplates"))
{
    Mkdir "c:\temp\UltimaIntuneTemplates"
}

#Change directory
cd C:\Temp\UltimaIntuneTemplates

# Start logging
Start-Transcript "c:\temp\UltimaIntuneTemplates\Template_Customer_Rebranding.log"

#Execute Changes
cls 

write-host "1. Changing EdgeHomePage URL in Device Configuration Profiles" -ForegroundColor Green
((Get-Content -path $JSON1 -Raw) -replace 'Replace_EdgeHomePageURL',$EdgeHomePageURL) | Set-Content -Path $JSON1
((Get-Content -path $JSON2 -Raw) -replace 'Replace_EdgeHomePageURL',$EdgeHomePageURL) | Set-Content -Path $JSON2
Write-host ""

write-host "2. Changing IE Homepage URL in Adminstrative Template" -ForegroundColor Green
((Get-Content -path $JSON3 -Raw) -replace 'Replace_HomepageURL',$HomePageURL) | Set-Content -Path $JSON3
Write-host ""

write-host "3. Changing Edge TabPage URL in Device Configuration Profiles" -ForegroundColor Green
((Get-Content -path $JSON1 -Raw) -replace 'Replace_EdgeTabPageURL',$EdgeTabPageURL) | Set-Content -Path $JSON1
((Get-Content -path $JSON2 -Raw) -replace 'Replace_EdgeTabPageURL',$EdgeTabPageURL) | Set-Content -Path $JSON2
Write-host ""

write-host "4. Changing Defender Security Center Support Name in Endpoint Protection Profile" -ForegroundColor Green
((Get-Content -path $JSON5 -Raw) -replace 'Replace_DefenderSecurityCenterSupportName',$DefenderSecurityCenterSupportName) | Set-Content -Path $JSON5
Write-host ""

write-host "5. Changing Azure AD Tenant Authentication Domain in Device Configuration Profiles" -ForegroundColor Green
((Get-Content -path $JSON1 -Raw) -replace 'Replace_TenantAuthDomain',$TenantAuthDomain) | Set-Content -Path $JSON1
((Get-Content -path $JSON2 -Raw) -replace 'Replace_TenantAuthDomain',$TenantAuthDomain) | Set-Content -Path $JSON2
Write-host ""

write-host "6. Changing Chrome Homepage and RestoreOnStartup URL in Chrome Configuration Profile" -ForegroundColor Green
((Get-Content -path $JSON4 -Raw) -replace 'Replace_ChromeHomePageLocation',$ChromeHomePageLocation) | Set-Content -Path $JSON4
((Get-Content -path $JSON4 -Raw) -replace 'Replace_ChromeRestoreOnStartupURL',$ChromeRestoreOnStartupURL) | Set-Content -Path $JSON4
Write-host ""

if ($PolicyNamePrefix -ne "ADJ_")
{

write-host "7. Changing policy Name prefixes" -ForegroundColor Green


#Replace default prefix with $PolicyNamePrefix within each file

ls c:\temp\UltimaIntuneTemplates\*.* -rec | %{$f=$_; (gc $f.PSPath) | %{$_ -replace "UK_Windows_", $PolicyNamePrefix} | sc $f.PSPath}

#Change prefix UK_Windows_ to $PolicyNamePrefix for all filenames

Get-ChildItem c:\temp\UltimaIntuneTemplates\ -Recurse -Include UK_Windows_* | Rename-Item -NewName { $_.Name.replace("UK_Windows_",$PolicyNamePrefix) }

}


<################Import Ultima Configuration Template ####################>

Start-IntuneRestoreConfig -Path c:\temp\UltimaIntuneTemplates\


<###############Create Azure Ad Groups ####################>

#Create Dynamic Security Groups

$DynamicSecurityGroups = @(
    [pscustomobject]@{Group="ADJ_Autopilot_Group1";Description="Used in conjunction with Autopilot Service and Office 365 app suite deployment";MembershipRule="(device.devicePhysicalIds -any _ -eq ""[OrderID]:UKM365Apps"")"}
    [pscustomobject]@{Group="ADJ_Autopilot_Group2";Description="Used in conjunction with Autopilot Service and Office 2016 app suite deployment";MembershipRule="(device.devicePhysicalIds -any _ -eq ""[OrderID]:UKO2016"")"}
    )

$DynamicSecurityGroups | ForEach-Object {

if (Get-AzureADMSGroup -SearchString $_.Group)
 {
$GroupName = $_.Group
Write-Warning "A Group $GroupName already exists in Azure Active Directory."
 }

else
 {
New-AzureADMSGroup -DisplayName $_.Group -Description $_.Description -MailEnabled $False -MailNickName "group" -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule $_.MembershipRule -MembershipRuleProcessingState "On"
 }

}

#Create Assgined Security Groups

$GeneralUserProfiles = $GroupNamePrefix + "GeneralUserProfiles"
$GeneralDeviceProfiles = $GroupNamePrefix + "GeneralDeviceProfiles"
$StandardDesktop_Group1 = $GroupNamePrefix + "StandardDesktop_Group1"
$StandardDesktop_Group2 = $GroupNamePrefix + "StandardDesktop_Group2"
$WU_Test_Ring = $GroupNamePrefix + "WU_Test_Ring"
$WU_Pilot_Ring = $GroupNamePrefix + "WU_Pilot_Ring"
$WU_Production_Ring = $GroupNamePrefix + "WU_Production_Ring"
$MDMEnrollment_Group1 = $GroupNamePrefix + "MDMEnrollment_Group1"
$LocalUserAdmin = $GroupNamePrefix + "LocalUserAdmin"
$WHfB = $GroupNamePrefix + "WHfB"

$AssignedSecurityGroups = @(
    [pscustomobject]@{Group="$GeneralUserProfiles";Description="Used to assign core user based Configuration Profiles and Applications"}
    [pscustomobject]@{Group="$GeneralDeviceProfiles";Description="Used to assign core device based Configuration Profiles and Application"}
    [pscustomobject]@{Group="$StandardDesktop_Group1";Description="User assigned general device restrictions and Microsoft 365 Apps based start layout"}
    [pscustomobject]@{Group="$StandardDesktop_Group2";Description="Used assigned general device restrictions and Office 2016 Apps based start layout"}
    [pscustomobject]@{Group="$WU_Test_Ring";Description="Used to assign Windows 10 test update deployment ring for Quality and Feature update testing"}
    [pscustomobject]@{Group="$WU_Pilot_Ring";Description="Used to assign Windows 10 pilot update deployment ring for Quality and Feature update pilot group deployment"}
    [pscustomobject]@{Group="$WU_Production_Ring";Description="Used to assign Windows 10 production deployment ring for Quality and Feature Updates production deployment"}
    [pscustomobject]@{Group="$MDMEnrollment_Group1";Description="User group for for automated MDM enrollment"}
    [pscustomobject]@{Group="$LocalUserAdmin";Description="Used to set Primary user of a device as a local administrator"}
    [pscustomobject]@{Group="$WHfB";Description="User group used to enable Windows Hello for Business"}

    )


$AssignedSecurityGroups| ForEach-Object {

if (Get-AzureADGroup -SearchString $_.Group)
 {
$GroupName = $_.Group
Write-Warning "A Group $GroupName already exists in Azure Active Directory."
 }

else
 {
New-AzureADGroup -DisplayName $_.Group -Description $_.Description -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet"
 }

}


<###############Assign Groups To Profiles############>
write-host ""
write-host "8. Assign Groups to Profiles" -ForegroundColor Green
write-host ""

#Create User targeted profile variables
$ApplicationControlPolicy = $PolicyNamePrefix + "ApplicationControl"
$DR_WithM365Apps_StartLayout = $PolicyNamePrefix + "DR_WithM365Apps_StartLayout"
$DR_WithO2016_StartLayout  = $PolicyNamePrefix + "DR_WithO2016_StartLayout"
$EPProtection  = $PolicyNamePrefix + "EPProtection"
$Windows_Settings_Chrome  = $PolicyNamePrefix + "Windows_Settings_Chrome"
$Settings_Windows  = $PolicyNamePrefix + "Settings_Windows"
$Windows_Compliance  = $PolicyNamePrefix + "Windows_Compliance"
$Windows_MDMSecurityBaseLine  = $PolicyNamePrefix + "Windows_MDMSecurityBaseLine"
$localadmin  = $PolicyNamePrefix + "localadmin"


#Create device targeted Profile variables
$DeliveryOptimisation = $PolicyNamePrefix + "DeliveryOptimisation"
$IDProtection = $PolicyNamePrefix + "IDProtection"
$AdminTemplates = $PolicyNamePrefix + "AdminTemplates"
$Bitlocker = $PolicyNamePrefix + "Bitlocker"
$MSDefender_AV = $PolicyNamePrefix + "MSDefender_AV"
$MSDefender_AVExclusions = $PolicyNamePrefix + "MSDefender_AVExclusions"
$Firewall = $PolicyNamePrefix + "Firewall"
$FirewallRules = $PolicyNamePrefix + "FirewallRules"
$PowerManagement = $PolicyNamePrefix + "PowerManagement’"
$AdminTemplates = $PolicyNamePrefix + "AdminTemplates"
$Comgt_M365Apps = $PolicyNamePrefix + "Comgt_M365Apps"
$WU_01_Test_Ring = $PolicyNamePrefix + "WU_01_Test_Ring"
$WU_02_Pilot_Ring= $PolicyNamePrefix + "WU_02_Pilot_Ring"
$WU_03_Production_Ring = $PolicyNamePrefix + "WU_03_Production_Ring"



#Assign groups to user targeted profiles

$UserTargetedProfileAssign = @(
    [pscustomobject]@{Policy=$ApplicationControlPolicy;Group=$GeneralUserProfiles;Type='DeviceConfig'}
    [pscustomobject]@{Policy=$DR_WithM365Apps_StartLayout;Group=$StandardDesktop_Group1;Type='DeviceConfig'}
    [pscustomobject]@{Policy=$DR_WithO2016_StartLayout;Group=$StandardDesktop_Group2;Type='DeviceConfig'}
    [pscustomobject]@{Policy=$EPProtection;Group=$GeneralUserProfiles;Type='DeviceConfig'}
    [pscustomobject]@{Policy=$Windows_Settings_Chrome;Group=$GeneralUserProfiles;Type='DeviceConfig'}
    [pscustomobject]@{Policy=$Settings_Windows;Group=$GeneralUserProfiles;Type='DeviceConfig'}
    [pscustomobject]@{Policy=$Windows_Compliance;Group=$GeneralUserProfiles;Type='Compliance'}
    [pscustomobject]@{Policy=$Windows_MDMSecurityBaseLine;Group=$GeneralUserProfiles;Type='Intent'}
    [pscustomobject]@{Policy=$localadmin;Group=$localUserAdmin;Type='DeviceConfig'}

)


$UserTargetedProfileAssign | ForEach-Object {Set-DeviceConfigAssignments}




#Assign groups to device targeted profiles

$DeviceTargetedProfileAssign = @(
    [pscustomobject]@{Policy=$DeliveryOptimisation;Group=$GeneralDeviceProfiles;Type='DeviceConfig'}
    [pscustomobject]@{Policy=$IDProtection;Group=$GeneralDeviceProfiles;Type='DeviceConfig'}
    [pscustomobject]@{Policy=$AdminTemplates;Group=$GeneralDeviceProfiles;Type='ADMX'}
    [pscustomobject]@{Policy=$Bitlocker;Group=$GeneralDeviceProfiles;Type='Intent'}
    [pscustomobject]@{Policy=$MSDefender_AV;Group=$GeneralDeviceProfiles;Type='Intent'}
    [pscustomobject]@{Policy=$MSDefender_AVExclusions;Group=$GeneralDeviceProfiles;Type='Intent'}
    [pscustomobject]@{Policy=$Firewall;Group=$GeneralDeviceProfiles;Type='Intent'}
    [pscustomobject]@{Policy=$FirewallRules;Group=$GeneralDeviceProfiles;Type='Intent'}
    [pscustomobject]@{Policy=$PowerManagement;Group=$GeneralDeviceProfiles;Type='DeviceConfig'}
    [pscustomobject]@{Policy=$Comgt_M365Apps;Group=$GeneralDeviceProfiles;Type='ADMX'}
    [pscustomobject]@{Policy=$WU_01_Test_Ring;Group=$WU_Test_Ring;Type='DeviceConfig'}
    [pscustomobject]@{Policy=$WU_02_Pilot_Ring;Group=$WU_Pilot_Ring;Type='DeviceConfig'}
    [pscustomobject]@{Policy=$WU_03_Production_Ring;Group=$WU_Production_Ring;Type='DeviceConfig'}
)

$DeviceTargetedProfileAssign | ForEach-Object {Set-DeviceConfigAssignments}


<##
Foreach ($configid in $ConfigurationPolicyId) {
write-host $ConfigurationPolicyId
                                              }


cls
$DeviceTargetedProfileAssign | ForEach-Object {

if ($_.Type -eq 'ADMX') {

$deviceConfigurationObject = Get-ADMXPolicy | Where-Object displayName -eq $_.Policy
$ConfigurationPolicyId = $deviceConfigurationObject.id
write-host $ConfigurationPolicyId

if($ConfigurationPolicyId -eq $null -or $ConfigurationPolicyId -eq ""){

    Write-Host "Configuration Policy ID for $_.Policy doesn't exist" -ForegroundColor Red
    Write-Host
    exit

    }
                         }


}

https://timmyit.com/2019/12/04/get-all-assigned-intune-policies-and-apps-per-azure-ad-group/
$deviceConfigurationObject = Get-DeviceManagement_DeviceConfigurations.displayname | Get-MSGraphAllPages | Where-Object displayName -eq "$AdminTemplates"
Get-DeviceManagement_DeviceConfigurations | Where { $PSItem.'DisplayName' -like '*$AdminTemplates*' }
(Get-DeviceManagement_DeviceConfigurations).DisplayName | Get-MSGraphAllPages
(Get-DeviceManagementIntent).DisplayName | Get-MSGraphAllPages
(Get-ADMXPolicy).DisplayName

(Get-IntuneDeviceConfigurationPolicy).DisplayName | Get-MSGraphAllPages
(Get-DeviceManagement_DeviceConfigurations).DisplayName | Get-MSGraphAllPages | Where-Object displayName -eq $PowerManagement

Connect-MSGraph -ForceInteractive
Update-MSGraphEnvironment -SchemaVersion beta
Connect-MSGraph

$deviceConfigurationObject = Get-ADMXPolicy | Where-Object displayName -eq $AdminTemplates
$ConfigurationPolicyId = $deviceConfigurationObject.id

(Get-ADMXPolicy).DisplayName, (Get-ADMXPolicy).ID


Remove-ADMXTemplateConfiguration -id fb49c7ef-0503-4bf2-a42d-e1d06fc52f37


# Administrative templates
$Resource = "deviceManagement/groupPolicyConfigurations"
$graphApiVersion = "Beta"
$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$expand=Assignments"
$ADMT = Invoke-MSGraphRequest -HttpMethod GET -Url $uri
$AllADMT = $ADMT.value
Write-host "Number of Device Administrative Templates found: $($AllADMT.DisplayName.Count)" -ForegroundColor cyan
Foreach ($Config in $AllADMT) {
 
Write-host $Config.DisplayName "   " $Config.ID -ForegroundColor Yellow
#Write-host $Config -ForegroundColor Yellow

}

Remove-DeviceConfigurationPolicy -id ff42f5ef-b27c-4e8d-84f3-57f3bb5cbff9
Get-ADMXPolicy -id 04130c85-ed27-48b3-ae53-205c46ecbb3f
###>



#Delete template device configuration assignments



Stop-Transcript
