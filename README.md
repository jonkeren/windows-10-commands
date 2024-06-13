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
Rename these 4 exe-files.
```
- C:\Program Files (x86)\Adobe\Adobe Sync\CoreSync\CoreSync.exe
- C:\Program Files\Adobe\Adobe Creative Cloud Experience\CCXProcess.exe
- C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ADS\Adobe Desktop Service.exe
- C:\Program Files\Common Files\Adobe\Creative Cloud Libraries\CCLibrary.exe
```

### Make Windows Explorer faster 
Windows Explorer can be really slow if the folder has a lot of files.
Can be solved with:
```
[HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell]
"FolderType"="NotSpecified"
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

### Disable Windows Defender (ToggleDefender)
https://github.com/AveYo/LeanAndMean/blob/main/ToggleDefender.bat

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

### WinGet upgrade all installed software
`winget upgrade --all`

### Windows 10 misc tweaks
```
# Remove Default Fax Printer
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue

# Uninstall Microsoft XPS Document Writer
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null

# Uninstall Work Folders Client
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null

# Disable Xbox features
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

# Disable creation of Thumbs.db thumbnail cache files
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1

# Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"

# Hide 3D Objects icon from This PC - The icon remains in personal folders and open/save dialogs
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

# Change default Explorer view to This PC
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

# Show hidden files
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1

# Show known file extensions
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

# Set Control Panel view to Large icons (Classic)
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0

# Show all tray icons
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0

# Hide Taskbar People icon
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

# Hide Taskbar Search icon / box
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

# Show file operations details
	New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1

# Show shutdown options on lock screen
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1

# Stop and disable Windows Search indexing service
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
	
# Disable Autorun for all drives
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

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

# Disable Application suggestions and automatic installation
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" | Out-Null
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
	
# Disable Web Search in Start Menu
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
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

### Windows 10 remove Xbox bloatware
```
reg add "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
sc config XblAuthManager start= disabled
sc config XblGameSave start= disabled
sc config XboxGipSvc start= disabled
sc config XboxNetApiSvc start= disabled
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable
takeown /f "%WinDir%\System32\GameBarPresenceWriter.exe" /a
icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /grant:r Administrators:F /c
taskkill /im GameBarPresenceWriter.exe /f
move "C:\Windows\System32\GameBarPresenceWriter.exe" "C:\Windows\System32\GameBarPresenceWriter.OLD"
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable
takeown /f "%WinDir%\System32\bcastdvr.exe" /a
icacls "%WinDir%\System32\bcastdvr.exe" /grant:r Administrators:F /c
taskkill /im bcastdvr.exe /f
move C:\Windows\System32\bcastdvr.exe C:\Windows\System32\bcastdvr.OLD
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
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
