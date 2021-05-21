<#
.SYNOPSIS
 - Windows 10 branding script run during Autopilot device setup
 - Adapted from Michael Niehaus original branding script: https://github.com/mtniehaus/AutopilotBranding
    
.DESCRIPTION
 - STEP 1: Set time zone (if specified)
 - STEP 2: Remove specified default apps if they exist
 - STEP 3: Install OneDrive per machine
 - STEP 4: Don't let Edge create a desktop shortcut (roams to OneDrive, creates mess)
 - STEP 5: Add features on demand (.Net Framework and language packs (dependant on Language packs being installed from Microsoft Store during Autopilot)
 - STEP 6: Set default file association to apps
 - STEP 7: Disable network location fly-out
 - STEP 8: Disable new Edge desktop icon
 - STEP 9: Enable LSA Protection
 - STEP 10 : Copy Local files to Program Files folders e.g. MS Word Templates, Fonts Etc
 - STEP 11: Disable Language Pack Cleanup
 - STEP 12: Install preferred language pack
 - STEP 13: Add Windows Hello Facial recognition feature
 - STEP 14: Disable Fast startup to work around windows update issue detailed here : https://docs.microsoft.com/en-US/troubleshoot/windows-client/deployment/updates-not-install-with-fast-startup 
 - STEP 15: Configure background
 - STEP 16: Configure OEM branding info
 - STEP 17: Enable UE-V
 
 
.EXAMPLE
    1. Modify config.xml, Associations.xml and language.xml to meet requirements
    2. Hash out / in required / not required steps and save.
    3. For steps 15 and 16 replace relevant branding files.
    4. Create IntuneWIN containing Autopilot Branding folder structure, e.g. : intunewinapputil.exe -c .\AutopilotBranding -s AutopilotBranding.ps1 -o .\ -q
    2. Open endpoint.microsoft.com
    3. Browse to Devices > Windows > PowerShell Scripts
    4. Attach this script
    5. Run in system context
    6. Assign to a user group
    7. Ensure the required Language experience packs (LXP) are installed via Microsoft Store + commands run to install the individual features (see associated Autopilot Branding Script)
   
.NOTES
    Version:          1.0.0
    Author:           Stuart Sims
    Creation Date:    18/05/2021
    Purpose/Change:   Initial script development
#>

# If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64")
{
    if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe")
    {
        & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"
        Exit $lastexitcode
    }
}

# Create a tag file just so Intune knows this was installed
if (-not (Test-Path "$($env:ProgramData)\Microsoft\AutopilotBranding"))
{
    Mkdir "$($env:ProgramData)\Microsoft\AutopilotBranding"
}
Set-Content -Path "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag" -Value "Installed"

# Start logging
Start-Transcript "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.log"

# PREP: Load the Config.xml
$installFolder = "$PSScriptRoot\"
Write-Host "Install folder: $installFolder"
Write-Host "Loading configuration: $($installFolder)Config.xml"
[Xml]$config = Get-Content "$($installFolder)Config.xml"


# STEP 1: Set time zone (if specified)
if ($config.Config.TimeZone) {
	Write-Host "Setting time zone: $($config.Config.TimeZone)"
	Set-Timezone -Id $config.Config.TimeZone
}
else {
	# Enable location services so the time zone will be set automatically (even when skipping the privacy page in OOBE) when an administrator signs in
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Allow" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type "DWord" -Value 1 -Force
	Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue
}

# STEP 2: Remove specified default apps if they exist
Write-Host "Removing specified in-box provisioned apps"
$apps = Get-AppxProvisionedPackage -online
$config.Config.RemoveApps.App | % {
	$current = $_
	$apps | ? {$_.DisplayName -eq $current} | % {
		Write-Host "Removing provisioned app: $current"
		$_ | Remove-AppxProvisionedPackage -Online | Out-Null
	}
}

# STEP 3: Install OneDrive per machine
if ($config.Config.OneDriveSetup) {
	Write-Host "Downloading OneDriveSetup"
	$dest = "$($env:TEMP)\OneDriveSetup.exe"
	$client = new-object System.Net.WebClient
	$client.DownloadFile($config.Config.OneDriveSetup, $dest)
	Write-Host "Installing: $dest"
	$proc = Start-Process $dest -ArgumentList "/allusers" -WindowStyle Hidden -PassThru
	$proc.WaitForExit()
	Write-Host "OneDriveSetup exit code: $($proc.ExitCode)"
}

# STEP 4: Don't let Edge create a desktop shortcut (roams to OneDrive, creates mess)
Write-Host "Turning off (old) Edge desktop shortcut"
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v DisableEdgeDesktopShortcutCreation /t REG_DWORD /d 1 /f /reg:64 | Out-Host

# STEP 5: Add features on demand (.Net Framework)
$currentWU = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Ignore).UseWuServer
if ($currentWU -eq 1)
{
	Write-Host "Turning off WSUS"
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 0
	Restart-Service wuauserv
}
$config.Config.AddFeatures.Feature | % {
	Write-Host "Adding Windows feature: $_"
	Add-WindowsCapability -Online -Name $_
}
if ($currentWU -eq 1)
{
	Write-Host "Turning on WSUS"
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 1
	Restart-Service wuauserv
}

# STEP 6: Set default file association to apps
if ($config.Config.DefaultApps) {
	Write-Host "Setting default apps: $($config.Config.DefaultApps)"
	& Dism.exe /Online /Import-DefaultAppAssociations:`"$($installFolder)$($config.Config.DefaultApps)`"
}

# STEP 7: Disable network location fly-out

Write-Host "Turning off network location fly-out"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f

# STEP 8: Disable new Edge desktop icon
Write-Host "Turning off Edge desktop icon"
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "CreateDesktopShortcutDefault" /t REG_DWORD /d 0 /f /reg:64 | Out-Host

# STEP 9: Enable LSA Protection
Write-Host "Enable LSA Protection in Audit Mode"
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe") -ne $true) 
{  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -force -ea SilentlyContinue | Out-Null }

reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f /reg:64 | Out-Host
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f /reg:64 | Out-Host

# STEP 10 : Copy Local files to Program Files folders e.g. MS Word Templates, Fonts Etc
Write-Host "Copy files"

Expand-Archive -LiteralPath '.\{ZIPFILENAME}.zip' -DestinationPath "C:\Program Files (x86)\" -Force
Expand-Archive -LiteralPath '.\{ZIPFILENAME}.zip' -DestinationPath "C:\Program Files\" -Force

# STEP 11: Disable Language Pack Cleanup
# To prevent this issue : https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/language-packs-known-issue
REG.exe add "HKLM\Software\Policies\Microsoft\Control Panel\International" /v BlockCleanupOfUnusedPreinstalledLangPacks /t REG_DWORD /d 1 /f /reg:64

# STEP 12: Install preferred language pack
Write-Host "Install preferred language pack"

if ($config.Config.Language) {
	Write-Host "Configuring language using: $($config.Config.Language)"
	& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$($installFolder)$($config.Config.Language)`""
}

<# STEP 13: Add Windows Hello Facial recognition feature
Write-Host "Add Windows Hello facial recognition feature"
Get-WindowsCapability -online | Where-Object {$_.name -like 'Hello.Face*'} | Add-WindowsCapability -online
#>

# STEP 14: Disable Fast startup to work around windows update issue detailed here : https://docs.microsoft.com/en-US/troubleshoot/windows-client/deployment/updates-not-install-with-fast-startup 

$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
$Name = "HiberbootEnabled"
$value = "0"
 
#Check if $Path exist. If not, create $Path and then add the item and set value.
 
If (!(Test-Path $Path))
 
{
    New-Item -Path $Path -Force | Out-Null
    New-ItemProperty -Path $Path -Name $Name -Value $value -PropertyType DWORD -Force | Out-Null
}
 
 ELSE
{
    New-ItemProperty -Path $Path -Name $Name -Value $value -PropertyType DWORD -Force | Out-Null
}

<# STEP 15: Configure background
Write-Host "Setting up Autopilot theme"
Mkdir "C:\Windows\Resources\OEM Themes" -Force | Out-Null
Copy-Item "$installFolder\Autopilot.theme" "C:\Windows\Resources\OEM Themes\Autopilot.theme" -Force
Mkdir "C:\Windows\web\wallpaper\Autopilot" -Force | Out-Null
Copy-Item "$installFolder\Autopilot.jpg" "C:\Windows\web\wallpaper\Autopilot\Autopilot.jpg" -Force
Write-Host "Setting Autopilot theme as the new user default"
reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Host
reg.exe add "HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v InstallTheme /t REG_EXPAND_SZ /d "%SystemRoot%\resources\OEM Themes\Autopilot.theme" /f | Out-Host
reg.exe unload HKLM\TempUser | Out-Host
#>

<# STEP 16: Configure OEM branding info
if ($config.Config.OEMInfo)
{
	Write-Host "Configuring OEM branding info"

	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Manufacturer /t REG_SZ /d "$($config.Config.OEMInfo.Manufacturer)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Model /t REG_SZ /d "$($config.Config.OEMInfo.Model)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportPhone /t REG_SZ /d "$($config.Config.OEMInfo.SupportPhone)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportHours /t REG_SZ /d "$($config.Config.OEMInfo.SupportHours)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportURL /t REG_SZ /d "$($config.Config.OEMInfo.SupportURL)" /f /reg:64 | Out-Host
	Copy-Item "$installFolder\$($config.Config.OEMInfo.Logo)" "C:\Windows\$($config.Config.OEMInfo.Logo)" -Force
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Logo /t REG_SZ /d "C:\Windows\$($config.Config.OEMInfo.Logo)" /f /reg:64 | Out-Host
}
#>

<# STEP 17: Enable UE-V
Write-Host "Enabling UE-V"
Enable-UEV
Set-UevConfiguration -Computer -SettingsStoragePath "%OneDriveCommercial%\UEV" -SyncMethod External -DisableWaitForSyncOnLogon
Get-ChildItem "$($installFolder)UEV" -Filter *.xml | % {
	Write-Host "Registering template: $($_.FullName)"
	Register-UevTemplate -Path $_.FullName
	
}
#>

Stop-Transcript
