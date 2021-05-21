<#
.SYNOPSIS
 - Sets default speech language to defined preferred language
 - Disables language sync to prevent language preferences being overwritten by Enterprise state Roaming captured settings
 - Runs language resource reconcile task sequence to avoid delays to updating language preferences
 - Sets the defined preferred language and removes US
 - Schedules the changes to happen at logon
    
.DESCRIPTION
 - Designed to run post a Windows 10 Autopilot deployment
 - At first logon the preferred language together with any defined secondary language as well as Regional Format, Keyboard, Speech, Apps and websites settings.
 - At second logon the Windows display language is set and activated on the subsequent logon.
 - Log path C:\Windows\Temp
 - Local file install location : C:\ProgramData\Set-DefaultLanguage
 
.EXAMPLE
    1. Define the preferred language settings in section 1.1 'Language preference variables'
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
                      
###########################################################################################
# 1.0 Start transcript for logging
###########################################################################################

Start-Transcript -Path $(Join-Path $env:temp "SetLanguage.log")

#check if running as system
function Test-RunningAsSystem {
	[CmdletBinding()]
	param()
	process {
		return [bool]($(whoami -user) -match "S-1-5-18")
	}
}

###########################################################################################
# 1.1 Language preference variables
###########################################################################################

$PrimaryLanguage = "en-GB" # Primary Language string, ref: https://docs.microsoft.com/en-us/cpp/c-runtime-library/language-strings?view=msvc-160
$SecondaryLanguage = "en-US" # Secondary Language string, ref: {as per above url}
$PrimaryInputCode = "0809:00000809" # Primary Keyboard Language, ref: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-8.1-and-8/hh825682(v=win.10)
$SecondaryInputCode = "0409:00000409" # Secondary Keyboard Language, ref: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-8.1-and-8/hh825682(v=win.10)
$PrimaryGeoID = "242" # Geographical location identifier (decimal), ref: https://docs.microsoft.com/en-us/windows/win32/intl/table-of-geographical-locations
$AddSecondary = "Yes"  #Set to yes to add a Secondary language
$RemoveSecondary = "Yes" # Set to yes to remove secondary language from list


###########################################################################################
# 2.0 Start of user context script
###########################################################################################

if (-not (Test-RunningAsSystem)) {

###########################################################################################
# 2.1 Create Functions
###########################################################################################

function SetSpeechLanguage {
       if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\SpeechRecognizer") -ne $true) 
{  New-Item "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\SpeechRecognizer" -force -ea SilentlyContinue | Out-Null }
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\SpeechRecognizer" -Name 'RecognizedLanguage' -Type "String" -Value $PrimaryLanguage -Force
    }

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

##############################################################################################################################################################
# 2.2 Disable language sync to prevent language preferences being overwritten by other device configurations synced through Enterprise State Roaming
##############################################################################################################################################################

Write-host "Calling function to disable Language Preference Sync"
Disable-LanguageSync

###############################################################################################################
# 2.3 trigger 'LanguageComponentsInstaller\ReconcileLanguageResources' to avoid delay to language pack updating
###############################################################################################################

Start-ScheduledTask -TaskName "\Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources"
Start-Sleep 10

###############################################################################################################
# 2.4 Set preferred languages
###############################################################################################################

$NewLanguageList = New-WinUserLanguageList -Language $PrimaryLanguage

If (!($AddSecondary -ne 'Yes' -And $NewLanguageList.LanguageTag -ne $PrimaryLanguage))
 
{
#Only adds primary language
$NewLanguageList[1].InputMethodTips.Clear()
$NewLanguageList[1].InputMethodTips.Add($PrimaryInputCode)
Set-WinUserLanguageList $NewLanguageList -Force
}
 
ELSE
{
# Adds primary and secondary languages
$NewLanguageList.Add([Microsoft.InternationalSettings.Commands.WinUserLanguage]::new($SecondaryLanguage))
$NewLanguageList[1].InputMethodTips.Clear()
$NewLanguageList[1].InputMethodTips.Add($PrimaryInputCode)
$NewLanguageList[1].InputMethodTips.Add($SecondaryInputCode)
Set-WinUserLanguageList $NewLanguageList -Force
}

#Prevents display language being dynamically determined
Set-WinUILanguageOverride -Language $PrimaryLanguage

$CurrentSysLocale = (Get-WinSystemLocale)[0].Name
if ($CurrentSysLocale -eq $PrimaryLanguage) {Set-WinSystemLocale -SystemLocale $PrimaryLanguage}

$CurrentCulture = (Get-Culture)[0].Name
if ($CurrentCulture -eq $PrimaryLanguage) {Set-Culture -CultureInfo $PrimaryLanguage}

$CurrentHomeLocation = (Get-WinHomeLocation)[0].GeoId
if ($CurrentHomeLocation -eq $PrimaryGeoID) {Set-WinHomeLocation -GeoId $PrimaryGeoID}


###########################################################################################
# 2.5 Sets the default Speech Language to Primary Language
###########################################################################################

Write-host "Set Speech Language"
SetSpeechLanguage

###########################################################################################
# 2.6 Sets the default Speech Language to Primary Language
###########################################################################################

If (!($RemoveSecondary -eq 'Yes'))
 
{
$LangList = Get-WinUserLanguageList
$MarkedLang = $LangList | where LanguageTag -eq "en-US"
$LangList.Remove($MarkedLang)
Set-WinUserLanguageList $LangList -Force
}
 

###########################################################################################
# End & finish transcript and user context script
###########################################################################################
}
Stop-transcript

###########################################################################################
# Done
###########################################################################################

#!ENDOFUSERSCRIPT!#

###########################################################################################
# 3.0 Start of system context script
###########################################################################################

if (Test-RunningAsSystem) {

#Set System Local
Set-WinSystemLocale -SystemLocale $PrimaryLanguage

##########################################################################################
# 3.1 Sets the MUI Perffered UI Language to the defined primary language (run by System)
###########################################################################################

Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\Settings" -Name 'PreferredUILanguages' -Type "MultiString" -Value $PrimaryLanguage -Force

	
##########################################################################################
# 3.2 Get the current script path and content for the user script and save it to the client
###########################################################################################

Start-Transcript -Path $(Join-Path -Path $env:temp -ChildPath "SetLanguageScheduledTask.log")
	Write-Output "Running as System --> creating scheduled task to Set preferred Language"

	$currentScript = Get-Content -Path $($PSCommandPath)

	$schtaskScript = $currentScript[(0) .. ($currentScript.IndexOf("#!ENDOFUSERSCRIPT!#") - 1)]

	$scriptSavePath = $(Join-Path -Path $env:ProgramData -ChildPath "Set-DefaultLanguage")

	if (-not (Test-Path $scriptSavePath)) {

		New-Item -ItemType Directory -Path $scriptSavePath -Force
	}

	$scriptSavePathName = "SetDefaultLanguage.ps1"

	$scriptPath = $(Join-Path -Path $scriptSavePath -ChildPath $scriptSavePathName)

	$schtaskScript | Out-File -FilePath $scriptPath -Force

##########################################################################################
# 3.3 Create dummy vbscript to hide PowerShell Window popping up
##########################################################################################

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
# 3.4 Register a scheduled task to run for all users
###########################################################################################

	$schtaskName = "SetPreferredLanguage"
	$schtaskDescription = "Set preferred Language and Display Language and remove en-US from list"

###########################################################################################
# 3.5 Delete the scheduled task if it already exists
###########################################################################################

if ($(Get-ScheduledTask -TaskName $schtaskName -ErrorAction SilentlyContinue).TaskName -eq $schtaskName) {
Unregister-ScheduledTask -TaskName $schtaskName -Confirm:$False }
start-sleep -seconds 5

$trigger = New-ScheduledTaskTrigger -AtLogon
$principal= New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -Id "Author"

###########################################################################################
# 3.6 Call the vbscript helper and pass the PosH script as argument
###########################################################################################

$action = New-ScheduledTaskAction -Execute $wscriptPath -Argument "`"$dummyScriptPath`" `"$scriptPath`""
$settings= New-ScheduledTaskSettingsSet -Compatibility Win8 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$null=Register-ScheduledTask -TaskName $schtaskName -Trigger $trigger -Action $action -Principal $principal -Description $schtaskDescription -Settings $settings -Force
start-sleep -seconds 5

###########################################################################################
# 3.7 Create scheduled task, run immediately and then at each logon, retire after 14 days delete after 15 day.
###########################################################################################

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
