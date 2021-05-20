<#
.SYNOPSIS
 - Sets default speech language to defined preferred language
 - Disables language sync to prevent language preferences being overwritten by Enterprise state Roaming captured settings
 - Runs language resource reconcile task sequence to avoid delays to updating language preferences
 - Sets the defined preferred language and removes US
 - Schedules the changes to happen at logon
    
.DESCRIPTION
 - Designed to run post a Windows 10 Autopilot deployment
 - At first logon the preferred language is set as well as Regional Format, Keyboard, Speech, Apps and websites.
 - At second logon the Windows display language is set and activated on the subsequent logon.
 - Log path C:\Windows\Temp
 - Local file install location : C:\ProgramData\Set-DefaultLanguage
 - Credit to Nicola Sutter for local script construction and execution technique : https://github.com/nicolonsky
 
.EXAMPLE
    1. Define the preferred language settings in the 'Variables' section below and save.
    2. Open endpoint.microsoft.com
    3. Browse to Devices > Windows > PowerShell Scripts
    4. Attach this script
    5. Run in system context
    6. Assign to a user group
    Note: This script is dependant on the required Language experience pack (LXP) being installed via Microsoft Store + commands run to install the individual features (see associated Autopilot Branding Script)
   
.NOTES
    Version:          1.0.0
    Author:           Stuart Sims
    Creation Date:    18/05/2021
    Purpose/Change:   Initial script development
#>
                      
###########################################################################################
# Start transcript for logging
###########################################################################################

###########################################################################################
# Variables
###########################################################################################

Start-Transcript -Path $(Join-Path $env:temp "SetLanguage.log")
# Language codes
$PrimaryLanguage = "en-GB"
$SecondaryLanguage = "en-US"
$PrimaryInputCode = "0809:00000809"
$SecondaryInputCode = "0409:00000409"
$PrimaryGeoID = "242"

#check if running as system
function Test-RunningAsSystem {
	[CmdletBinding()]
	param()
	process {
		return [bool]($(whoami -user) -match "S-1-5-18")
	}
}

if (-not (Test-RunningAsSystem)) {

# Sets the default Speech Language to Primary Language

function SetSpeechLanguage {
       if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\SpeechRecognizer") -ne $true) 
{  New-Item "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\SpeechRecognizer" -force -ea SilentlyContinue | Out-Null }
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\SpeechRecognizer" -Name 'RecognizedLanguage' -Type "String" -Value $PrimaryLanguage -Force
    }

# Disable language sync to prevent language preferences being overwritten by other device configurations synced via Enterprise State Roaming

function Disable-LanguageSync {


        $LangSync = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"
        $ShownEnabledValue = Get-ItemProperty -Path $LangSync -Name "Enabled"
        if (-not(Test-Path -Path $LangSync)) {
            write-host "The key $LangSync does not exist and will be created"
            New-Item -Path $LangSync -Force | Out-Null
        }
        else {
        write-host "Registry key exists, continuing......."
        }
        if ($ShownEnabledValue.Enabled -ne 0) {
            Write-Host "The registry value Enabled does not exist or is not 1, creating registry value"
            Set-ItemProperty -Path  $LangSync -Name 'Enabled' -Type "DWord" -Value 0 -Force
        }
        else {
            Write-host "The registry Value exists and has a value of 0, we will do nothing."
        }
    }

Write-host "Calling function to disable Language Preference Sync"
Disable-LanguageSync

 # trigger 'LanguageComponentsInstaller\ReconcileLanguageResources' to avoid delay to language pack updating
Start-ScheduledTask -TaskName "\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources"
Start-Sleep 10
			
# Set preferred languages
$NewLanguageList = New-WinUserLanguageList -Language $PrimaryLanguage
if ($NewLanguageList.LanguageTag -ne $PrimaryLanguage) {
#$NewLanguageList.Add([Microsoft.InternationalSettings.Commands.WinUserLanguage]::new($SecondaryLanguage))
$NewLanguageList[1].InputMethodTips.Clear()
$NewLanguageList[1].InputMethodTips.Add($PrimaryInputCode)
}

#$NewLanguageList[1].InputMethodTips.Add($SecondaryInputCode)
$CurrentLangList = (get-winuserlanguagelist)[0].LanguageTag
if ($CurrentLangList -eq $PrimaryLanguage) {Set-WinUserLanguageList $NewLanguageList -Force}

Set-WinUILanguageOverride -Language $PrimaryLanguage

$CurrentSysLocale = (Get-WinSystemLocale)[0].Name
if ($CurrentSysLocale -eq $PrimaryLanguage) {Set-WinSystemLocale -SystemLocale $PrimaryLanguage}

$CurrentCulture = (Get-Culture)[0].Name
if ($CurrentCulture -eq $PrimaryLanguage) {Set-Culture -CultureInfo $PrimaryLanguage}

$CurrentHomeLocation = (Get-WinHomeLocation)[0].GeoId
if ($CurrentHomeLocation -eq $PrimaryGeoID) {Set-WinHomeLocation -GeoId $PrimaryGeoID}

# Sets the default Speech Language to defined primary language
Write-host "Set Speech Language"
SetSpeechLanguage

#Remove en-US Language Pack from preference list
$LangList = Get-WinUserLanguageList
$MarkedLang = $LangList | where LanguageTag -eq "en-US"
$LangList.Remove($MarkedLang)
Set-WinUserLanguageList $LangList -Force
}

###########################################################################################
# End & finish transcript
###########################################################################################

Stop-transcript

###########################################################################################
# Done
###########################################################################################

#!SCHTASKCOMESHERE!#

###########################################################################################
# If this script is running under system (IME) scheduled task is created  (recurring)
###########################################################################################

if (Test-RunningAsSystem) {

#Set System Local
Set-WinSystemLocale -SystemLocale $PrimaryLanguage

# Sets the MUI Perffered UI Language to the defined primary language (run by System)
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\Settings" -Name 'PreferredUILanguages' -Type "MultiString" -Value $PrimaryLanguage -Force

	Start-Transcript -Path $(Join-Path -Path $env:temp -ChildPath "SetLanguageScheduledTask.log")
	Write-Output "Running as System --> creating scheduled task to Set preferred Language"

	###########################################################################################
	# Get the current script path and content for the user script and save it to the client
	###########################################################################################

	$currentScript = Get-Content -Path $($PSCommandPath)

	$schtaskScript = $currentScript[(0) .. ($currentScript.IndexOf("#!SCHTASKCOMESHERE!#") - 1)]

	$scriptSavePath = $(Join-Path -Path $env:ProgramData -ChildPath "Set-DefaultLanguage")

	if (-not (Test-Path $scriptSavePath)) {

		New-Item -ItemType Directory -Path $scriptSavePath -Force
	}

	$scriptSavePathName = "SetDefaultLanguage.ps1"

	$scriptPath = $(Join-Path -Path $scriptSavePath -ChildPath $scriptSavePathName)

	$schtaskScript | Out-File -FilePath $scriptPath -Force
	
	
	###########################################################################################
	# Create dummy vbscript to hide PowerShell Window popping up
	###########################################################################################

	$vbsDummyScript = "
	Dim shell,fso,file

	Set shell=CreateObject(`"WScript.Shell`")
	Set fso=CreateObject(`"Scripting.FileSystemObject`")

	strPath=WScript.Arguments.Item(0)

	If fso.FileExists(strPath) Then
		set file=fso.GetFile(strPath)
		strCMD=`"powershell -nologo -executionpolicy ByPass -command `" & Chr(34) & `"&{`" &_
		file.ShortPath & `"}`" & Chr(34)
		shell.Run strCMD,0
	End If
	"

	$scriptSavePathName = "SetLanguage-VBSHelper.vbs"

	$dummyScriptPath = $(Join-Path -Path $scriptSavePath -ChildPath $scriptSavePathName)

	$vbsDummyScript | Out-File -FilePath $dummyScriptPath -Force

	$wscriptPath = Join-Path $env:SystemRoot -ChildPath "System32\wscript.exe"

	###########################################################################################
	# Register a scheduled task to run for all users
	###########################################################################################

	$schtaskName = "SetPreferredLanguage"
	$schtaskDescription = "Set preferred Language and Display Language and remove en-US from list"

#Delete the scheduled task if it already exists
if ($(Get-ScheduledTask -TaskName $schtaskName -ErrorAction SilentlyContinue).TaskName -eq $schtaskName) {
Unregister-ScheduledTask -TaskName $schtaskName -Confirm:$False }
start-sleep -seconds 5

$trigger = New-ScheduledTaskTrigger -AtLogon
$principal= New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -Id "Author"

#call the vbscript helper and pass the PosH script as argument
$action = New-ScheduledTaskAction -Execute $wscriptPath -Argument "`"$dummyScriptPath`" `"$scriptPath`""
$settings= New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$null=Register-ScheduledTask -TaskName $schtaskName -Trigger $trigger -Action $action -Principal $principal -Description $schtaskDescription -Settings $settings -Force
start-sleep -seconds 5

#Set failsafe scheduled task to run on first script run and at each logon, then retire after 14 days delete after 15 day.
$task = (Get-ScheduledTask -TaskName "$schtaskName")
$task.Triggers[0].EndBoundary = (Get-Date).AddDays(14).ToString('s')
$task.Settings.DeleteExpiredTaskAfter = "P16D"
Set-ScheduledTask -InputObject $task
start-sleep -seconds 5
Start-ScheduledTask -TaskName $schtaskName

}

###########################################################################################
# Done
###########################################################################################
