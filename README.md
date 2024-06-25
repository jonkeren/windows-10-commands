Here are some Windows 10 CLI / Powershell commands I use once in a while. Using this as my personal notepad, so to speak; might be useful for someone.

### Powershell command to create Firewall block rules for all .exe files in a directory
This will recurse the directory, and automatically add an incoming and outgoing block rule in the Windows Firewall to block all program's access to internet.
```
Get-ChildItem -Recurse -Path "DIRECTORY" *.exe |
    Select-Object Name,FullName |
    ForEach-Object `
    {New-NetFirewallRule -DisplayName "Block $($_.Name) Inbound" -Direction Inbound -Program "$($_.FullName)" -Action Block;
    New-NetFirewallRule -DisplayName "Block $($_.Name) Outbound" -Direction Outbound -Program "$($_.FullName)" -Action Block}
```
Directories to block for Adobe software: `C:\Program Files\Adobe`, `C:\Program Files (x86)\Adobe`, `C:\Program Files\Common Files\Adobe`, `C:\Program Files (x86)\Common Files\Adobe`.

### Windows 10/11 stop Adobe unnecessary Adobe Background processes
Rename these 5 exe-files.
```
- C:\Program Files (x86)\Adobe\Adobe Sync\CoreSync\CoreSync.exe
- C:\Program Files\Adobe\Adobe Creative Cloud Experience\CCXProcess.exe
- C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe
- C:\Program Files\Common Files\Adobe\Creative Cloud Libraries\CCLibrary.exe
- C:\Program Files (x86)\Adobe\Adobe Creative Cloud Experience\CCXProcess.exe
```

### Make Windows Explorer much faster 
Windows Explorer can be really slow if the folder has a lot of files.
Can be solved with:
```
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f
```

### Install free Windows 10 HEVC Video Extensions from Device Manufacturer
`start ms-windows-store://pdp/?ProductId=9n4wgh0z6vhq`

### Powershell create directories based on file extensions; and move the files to their extension directory. (This sorts files in one large directory into multiple subdirectories).
```
Get-ChildItem -File | % { Process { $_.Extension }} | Select -Unique | % { Process { New-Item $_ -ItemType Directory -Force }};
Get-ChildItem -File | % { Process { Move-Item $_ -Destination $_.Extension -Force }};
```

### Windows 10 / 11 keep modern standby, but disable network in standby.
```
POWERCFG -SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONNECTIVITYINSTANDBY 0
POWERCFG -SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONNECTIVITYINSTANDBY 0​
```

### Windows 10 / 11 Automatic activation
```
irm https://get.activated.win | iex
```
See: https://github.com/massgravel/Microsoft-Activation-Scripts

### CMD disable Windows 10/11 "Modern Standby" / "Connected Standby" (S0) and use S3
```
reg add HKLM\System\CurrentControlSet\Control\Power /v PlatformAoAcOverride /t REG_DWORD /d 0
reg add HKLM\System\CurrentControlSet\Control\Power /v CsEnabled /t REG_DWORD /d 0
reg add HKLM\System\CurrentControlSet\Control\Power /v EnforceDisconnectedStandby /t REG_DWORD /d 0
POWERCFG /SETACVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e SUB_NONE CONNECTIVITYINSTANDBY 0
POWERCFG /SETDCVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e SUB_NONE CONNECTIVITYINSTANDBY 0
```

### Windows 10 fix Logitech MX Anywhere 3 stutter/lag using registry change
Go to `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_8087&PID_0026\5&3b777946&0&14\Device Parameters`.
Device name and numer might be different. In this case the device name is "Intel(R) Wireless Bluetooth(R)".
Add 3 key/values:
```
"DeviceSelectiveSuspended"=dword:00000000 
"SelectiveSuspendEnabled"=dword:00000000 
"SelectiveSuspendSupported"=dword:00000000
```

### Disable Windows Defender (ToggleDefender and/or DefenderControl)
https://github.com/AveYo/LeanAndMean/blob/main/ToggleDefender.bat

https://www.sordum.org/9480/defender-control-v2-1/

### Powershell find invalid characters in path and/or file name:
`gci -recurse  . | where {$_.Name -match "[^\u0000-\u00FF]"} | select -expand FullName`

### Powershell recursively remove some files (also hidden and system) from subdirectories:
`Get-ChildItem -File -Include *.DS_Store -Recurse -Force | Remove-Item -Force -Verbose`

### CMD Make all Onedrive files and folders available locally, recursively:
`attrib +p -u /s /d`

### CMD Make all Onedrive files and folders available in the cloud only, recursively:
`attrib -p +u /s /d`

### Powershell delete all empty directories:
`Get-ChildItem -Recurse -Force . | where { $_.PSISContainer -and @( $_ | Get-ChildItem ).Count -eq 0 } | Remove-Item -Verbose -Force`

### Powershell rename all jpg images and videos, to strip the "IMG_" and "VID_" prefix, and to replace underscores with dashes:
`Get-ChildItem -Recurse 'IMG_20*.*' | Rename-Item -NewName { $_.Name -Replace 'IMG_20','20' } -Passthru`

`Get-ChildItem -Recurse 'VID_20*.*' | Rename-Item -NewName { $_.Name -Replace 'VID_20','20' } -Passthru`

`Get-ChildItem -Recurse '20??????_*.*' | Rename-Item -NewName { $_.Name -Replace '_','-' } -PassThru`

### Powershell Windows 10 debloat, with Gridview popup (so you can select which apps to remove):
`Get-AppXPackage | Out-GridView -Passthru | Remove-AppXPackage`

`Get-AppXPackage -AllUsers | Out-GridView -Passthru | Remove-AppXPackage`

`Get-AppxProvisionedPackage -Online | Out-GridView -PassThru | Remove-AppxProvisionedPackage -Online`

### Powershell to download / install / upgrade all current Microsoft Visual C++ Redistributables
`Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://vcredist.com/install.ps1'))`

### CMD Disk Cleanup old Drivers / Packages:
`rundll32.exe pnpclean.dll,RunDLL_PnpClean /DRIVERS /MAXCLEAN`

### CMD Windows 10 search indexer service OFF and ON (run CMD as administrator):
`sc stop “wsearch” && sc config “wsearch” start=disabled`

`sc config “wsearch” start=delayed-auto && sc start “wsearch”`

### CMD kill all tasks with a task name:
`taskkill /F /IM <NAME>.exe /T`

example, kill all Chrome processes:

`taskkill /F /IM chrome.exe /T`

### SFC / DISM commands
`sfc /scannow`

`Dism.exe /Online /Cleanup-Image /CheckHealth`

`DISM.exe /Online /Cleanup-Image /ScanHealth`

`Dism.exe /Online /Cleanup-Image /RestoreHealth`

`Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore`

`Dism.exe /online /Cleanup-Image /StartComponentCleanup`

`Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase`

`Dism.exe /online /Cleanup-Image /SPSuperseded`

`sfc /scannow`


### Powershell command to empty all EventViewer logs
`Get-WinEvent -ListLog * | where {$_.RecordCount} | ForEach-Object -Process { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) }`

### CMD command to empty all EventViewer logs
`for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`

### Windows 10 enable "God mode" icon on desktop
```
$DesktopPath = [Environment]::GetFolderPath("Desktop");
mkdir "$DesktopPath\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
```

### Windows 10/11 enable all power plan options/settings (unhide)
```
$jos = "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings"
$querylist =  reg query $jos
foreach ($regfolder in $querylist){
$querylist2 = reg query $regfolder
    foreach($2ndfolder in $querylist2){
    $active2 = $2ndfolder -replace "HKEY_LOCAL_MACHINE" , "HKLM:"
    Get-ItemProperty -Path $active2
    Set-ItemProperty -Path "$active2" -Name "Attributes" -Value '2'
    }
    $active = $regfolder -replace "HKEY_LOCAL_MACHINE" , "HKLM:"
    Get-ItemProperty -Path $active
    Set-ItemProperty -Path "$active" -Name "Attributes" -Value '2'
}
```
### Set Windows Store to DELL_Xps to download Dell Apps
`REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Store" /v StoreContentModifier /f /t REG_SZ /d DELL_Xps`

### Batch convert multiple PDF's to JPG's with CMD and Ghostscript
```
@echo off
setlocal

for %%I in (*.pdf) do (
    gswin64c.exe -dNOPAUSE -dBATCH -dNumRenderingThreads=4 -sDEVICE=jpeg -r300 -dJPEGQ=80 -dFirstPage=1 -dLastPage=1 -sOutputFile="%%~nI_p%%02d.jpg" "%%~I"
)
```


### Windows 10/11 misc. tweaks, settings, debloat. 
This is a fairly long list. I run these normally after a fresh Windows install. 
You can copy / paste this into an admin-Powershell window. All at once, or individually of course. Or, save as a .ps1 file and execute.
```
# Disable Xbox features
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage

# Disable Xbox GameDVR
	reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
	reg.exe add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f
	reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
	reg.exe add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f
	reg.exe add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f
	reg.exe add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
	reg.exe add "HKLM\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\System\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f
	reg.exe add "HKLM\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f

### Windows 10 remove Xbox bloatware
	reg.exe add "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
	Stop-Service -Name XblAuthManager
	Set-Service -Name XblAuthManager -StartupType Disabled
	Stop-Service -Name XblGameSave
	Set-Service -Name XblGameSave -StartupType Disabled
	Stop-Service -Name XboxGipSvc
	Set-Service -Name XboxGipSvc -StartupType Disabled
	Stop-Service -Name XboxNetApiSvc
	Set-Service -Name XboxNetApiSvc -StartupType Disabled
	schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable
	takeown /f "%WinDir%\System32\GameBarPresenceWriter.exe" /a
	icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /grant:r Administrators:F /c
	taskkill /im GameBarPresenceWriter.exe /f
	move "C:\Windows\System32\GameBarPresenceWriter.exe" "C:\Windows\System32\GameBarPresenceWriter.OLD"
	takeown /f "%WinDir%\System32\bcastdvr.exe" /a
	icacls "%WinDir%\System32\bcastdvr.exe" /grant:r Administrators:F /c
	taskkill /im bcastdvr.exe /f
	move C:\Windows\System32\bcastdvr.exe C:\Windows\System32\bcastdvr.OLD
	
# Uninstall Microsoft XPS Document Writer
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null

# Uninstall Work Folders Client
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
	
# Remove Default Fax Printer
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
	
# Disable Windows Update automatic restart
# Note: This doesn't disable the need for the restart but rather tries to ensure that the restart doesn't happen in the least expected moment. Allow the machine to restart as soon as possible anyway.
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
	
# Disable Windows Defender
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	
# Disable Defender Auto Sample Submission
	Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Continue | Out-Null

# Set Control Panel view to Large icons (Classic)
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0

# Show all tray icons
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0



## EXPLORER ##

# Make Explorer much faster by not scanning for folder types.
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f

# Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"

# Hide 3D Objects icon from This PC - The icon remains in personal folders and open/save dialogs
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

# Show file operations details
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
	
# Disable creation of Thumbs.db thumbnail cache files
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
	
# Explorer set display the status of ongoing operations, such as file copy, move, delete, etc.
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 1 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 1 /f

# Set File Explorer to Open This PC instead of Quick Access
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
	
# Enables Explorer show File Extensions
	reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f

# Disable Autorun for all drives
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

# Show hidden files
	Set-ItemProperty -Path "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1	
	

# Show shutdown options on lock screen
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1

# Prevents Dev Home Installation
	reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /f

# Windows 10 / 11 keep modern standby, but disable network in standby.
	POWERCFG -SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONNECTIVITYINSTANDBY 0
	POWERCFG -SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONNECTIVITYINSTANDBY 0

# Set Windows 10 search indexer service off and disabled.
	Stop-Service -Name WSearch
	Set-Service -Name WSearch -StartupType Disabled

# Prevents New Outlook for Windows Installation
	reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /f

# Prevents Chat Auto Installation & Removes Chat Icon
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d 3 /f

# Enable Long File Paths with Up to 32,767 Characters
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f

# Disables News and Interests
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f

# Disables Windows Consumer Features Like App Promotions etc.
	reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 0 /f

# Disable Cortana
	reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

# Disable Windows Ink Workspace
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v AllowWindowsInkWorkspace /t REG_DWORD /d 0 /f

# Disable Feedback Notifications
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f

# Disable the Advertising ID for All Users
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f

# Disable Windows Error Reporting
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f

# Disable Delivery Optimization
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f

# Disable Remote Assistance
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

# Search Windows Update for Drivers First
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 1 /f

# Hides the Meet Now Button on the Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f

# Set Registry Keys to Disable Wifi-Sense
	reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v Value /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v Value /t REG_DWORD /d 0 /f
	
# Disable Tablet Mode
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v TabletMode /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v TabletMode /t REG_DWORD /d 0 /f

# Disables the "Push To Install" feature in Windows
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d 1 /f

# DELETES SCHEDULED TASKS REGISTRY KEYS
# Deleting Application Compatibility Appraiser
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /f

# Deleting Customer Experience Improvement Program
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /f
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /f
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /f

# Deleting Program Data Updater
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /f
	
# Deleting QueueReporting
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}" /f

# Configure Maximum Password Age in Windows
	net.exe accounts /maxpwage:UNLIMITED

# Allow Execution of PowerShell Script Files
	Set-ExecutionPolicy -Scope 'LocalMachine' -ExecutionPolicy 'RemoteSigned' -Force

# Removes Microsoft Teams
	$TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
	$TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')
	Stop-Process -Name "*teams*" -Force -ErrorAction Continue
	if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
		# Uninstall app
		$proc = Start-Process $TeamsUpdateExePath "-uninstall -s" -PassThru
		$proc.WaitForExit()
	}
	Get-AppxPackage "*Teams*" | Remove-AppxPackage -ErrorAction Continue
	Get-AppxPackage "*Teams*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction Continue
	if ([System.IO.Directory]::Exists($TeamsPath)) {
		Remove-Item $TeamsPath -Force -Recurse -ErrorAction Continue
	}

# Uninstall Teams from Uninstall registry key UninstallString
	$us = (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like '*Teams*'}).UninstallString
	if ($us.Length -gt 0) {
		$us = ($us.Replace('/I', '/uninstall ') + ' /quiet').Replace('  ', ' ')
		$FilePath = ($us.Substring(0, $us.IndexOf('.exe') + 4).Trim())
		$ProcessArgs = ($us.Substring($us.IndexOf('.exe') + 5).Trim().replace('  ', ' '))
		$proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru
		$proc.WaitForExit()
	}

# Disables Telemetry; Scheduled Tasks
	$scheduledTasks = @(
		"Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
		"Microsoft\Windows\Application Experience\ProgramDataUpdater",
		"Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
		"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
		"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
		"Microsoft\Windows\Feedback\Siuf\DmClient",
		"Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
		"Microsoft\Windows\Windows Error Reporting\QueueReporting",
		"Microsoft\Windows\Application Experience\StartupAppTask",
		"Microsoft\Windows\Application Experience\PcaPatchDbTask",
		"Microsoft\Windows\Maps\MapsUpdateTask"
	)
	foreach ($task in $scheduledTasks) {
		schtasks /Change /TN $task /Disable
	}

# Disabling the Delivery of Personalized or Suggested Content Like App Suggestions, Tips, and Advertisements in Windows
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OEMPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v IsMiEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OEMPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v IsMiEnabled /t REG_DWORD /d 0 /f
	reg.exe delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
	reg.exe delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d 0 /f

# Removes Copilot
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce" /v "UninstallCopilot" /t REG_SZ /d "" /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce" /v "UninstallCopilot" /t REG_SZ /d "" /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f

# Align the taskbar to the left on Windows 11
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f

# Hides Search Icon on Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f

# Start Menu Customizations - disables Recommendations in the Start Menu
	reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /t REG_DWORD /d 0 /f

# Hides or Removes People from Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f

# Hides Task View Button on Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f

# Hides and Removes News and Interests from PC and Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f

# Disables Input Personalization Settings
	reg.exe add "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f

# Disables Automatic Feedback Sampling
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v AutoSample /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v ServiceEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v AutoSample /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v ServiceEnabled /t REG_DWORD /d 0 /f

# Disables App Diagnostics
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppDiagnostics" /v AppDiagnosticsEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppDiagnostics" /v AppDiagnosticsEnabled /t REG_DWORD /d 0 /f

# Disables Delivery Optimization
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f

# Disables Maps Auto Download
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Maps" /v AutoDownload /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Maps" /v AutoDownload /t REG_DWORD /d 0 /f

# Disables Telemetry and Ads
	reg.exe add "HKLM\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f

# Hides the Meet Now Button on the Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f

# Disables Bing Search in Start Menu
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f
	reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f
	
# Disable Bing Web Search in Start Menu
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1

# Enables NumLock on Startup
	reg.exe add "HKLM\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d 2 /f
	reg.exe add "HKEY_CURRENT_USER\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d 2 /f

# Disables Sticky Keys
	reg.exe add "HKLM\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d "506" /f
	reg.exe add "HKLM\Control Panel\Accessibility\StickyKeys" /v HotkeyFlags /t REG_SZ /d "58" /f
	reg.exe add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d "506" /f
	reg.exe add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v HotkeyFlags /t REG_SZ /d "58" /f

# Set: do not Update Last Access Time Stamp - This Can Improve File System Performance
	fsutil.exe behavior set disableLastAccess 1

#Removes Preinstalled Bloatware Apps
	Get-AppxProvisionedPackage -Online | Where-Object -Property 'DisplayName' -In -Value @(
	  'Microsoft.Microsoft3DViewer';
	  'Microsoft.BingSearch';
	  'Clipchamp.Clipchamp';
	  'Microsoft.549981C3F5F10';
	  'Microsoft.Windows.DevHome';
	  'MicrosoftCorporationII.MicrosoftFamily';
	  'Microsoft.WindowsFeedbackHub';
	  'Microsoft.GetHelp';
	  'microsoft.windowscommunicationsapps';
	  'Microsoft.WindowsMaps';
	  'Microsoft.ZuneVideo';
	  'Microsoft.BingNews';
	  'Microsoft.WindowsNotepad';
	  'Microsoft.MicrosoftOfficeHub';
	  'Microsoft.Office.OneNote';
	  'Microsoft.OutlookForWindows';
	  'Microsoft.Paint';
	  'Microsoft.MSPaint';
	  'Microsoft.People';
	  'Microsoft.PowerAutomateDesktop';
	  'MicrosoftCorporationII.QuickAssist';
	  'Microsoft.SkypeApp';
	  'Microsoft.ScreenSketch';
	  'Microsoft.MicrosoftSolitaireCollection';
	  'Microsoft.MicrosoftStickyNotes';
	  'MSTeams';
	  'Microsoft.Getstarted';
	  'Microsoft.Todos';
	  'Microsoft.WindowsSoundRecorder';
	  'Microsoft.BingWeather';
	  'Microsoft.ZuneMusic';
	  'Microsoft.WindowsTerminal';
	  'Microsoft.Xbox.TCUI';
	  'Microsoft.XboxApp';
	  'Microsoft.XboxGameOverlay';
	  'Microsoft.XboxGamingOverlay';
	  'Microsoft.XboxIdentityProvider';
	  'Microsoft.XboxSpeechToTextOverlay';
	  'Microsoft.GamingApp';
	  'Microsoft.YourPhone';
		'Microsoft.549981C3F5F10';
	  'Microsoft.MixedReality.Portal';
	  'Microsoft.Windows.Ai.Copilot.Provider';
	  'Microsoft.WindowsMeetNow';
	) | Remove-AppxProvisionedPackage -AllUsers -Online
		
#Removes Legacy Apps (Windows capabilities)
	Get-WindowsCapability -Online | Where-Object -FilterScript {
	  ($_.Name -split '~')[0] -in @(
		'Browser.InternetExplorer';
		'MathRecognizer';
		'Microsoft.Windows.Notepad';
		'OpenSSH.Client';
		'Microsoft.Windows.MSPaint';
		'App.Support.QuickAssist';
		'App.StepsRecorder';
		'Media.WindowsMediaPlayer';
		'Microsoft.Windows.WordPad';
	  );
	} | Remove-WindowsCapability -Online 

# CMD Disk Cleanup old Drivers / Packages:
	rundll32.exe pnpclean.dll,RunDLL_PnpClean /DRIVERS /MAXCLEAN

```
