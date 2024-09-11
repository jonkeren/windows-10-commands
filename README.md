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

### Powershell replace "right single quotation mark" in file names with normal tick/apostrophe
`Get-ChildItem -Recurse | where {$_.Name -match "\u2019"} | Rename-Item -NewName { $_.Name -Replace "\u2019","'" } -Passthru`

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
See here: --> https://gist.github.com/jonkeren/537dba7f7cf84e319c634f7e9af4f2f8


