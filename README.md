Here are some Windows 10 CLI / Powershell commands I use once in a while. Using this as my personal notepad, so to speak; might be useful for someone.


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

`Dism.exe /Online /Cleanup-Image /RestoreHealth`

`Dism.exe /online /Cleanup-Image /StartComponentCleanup`

`Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase`

### Powershell command to empty all EventViewer logs
`Get-WinEvent -ListLog * | where {$_.RecordCount} | ForEach-Object -Process { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) }`

### CMD command to empty all EventViewer logs
`for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`

### Auto install software packages with WinGet
```
winget install Google.Chrome
winget install Google.DriveFileStream
winget install 7zip.7zip
winget install KDE.digikam
winget install scottlerch.hosts-file-editor
winget install XnSoft.XnViewMP
winget install XnSoft.XnConvert
winget install WhatsApp.WhatsApp
winget install qBittorrent.qBittorrent
winget install TimKosse.FileZilla.Client
winget install Klocman.BulkCrapUninstaller
winget install TGRMNSoftware.BulkRenameUtility
winget install HandBrake.HandBrake
winget install SublimeHQ.SublimeText
winget install dokan-dev.Dokany
winget install Toggl.TogglDesktop
winget install AntibodySoftware.WizTree
winget install VideoLAN.VLC
winget install Notepad++.Notepad++
winget install Doxie.Doxie
winget install alcpu.CoreTemp
winget install calibre.calibre
winget install voidtools.Everything
winget install Foxit.FoxitReader
winget install Microsoft.VC++2015-2019Redist-x86
winget install Microsoft.VC++2015-2019Redist-x64
winget install Microsoft.VC++2013Redist-x86
winget install Microsoft.VC++2013Redist-x64
winget install Microsoft.VC++2015-2022Redist-x64
winget install Microsoft.VC++2015-2022Redist-x86
winget install Microsoft.VC++2017Redist-x86
winget install Microsoft.VC++2017Redist-x64
winget install Microsoft.VC++2015Redist-x86
winget install Microsoft.VC++2015Redist-x64
winget install Microsoft.VC++2012Redist-x86
winget install Microsoft.VC++2012Redist-x64
winget install Microsoft.VC++2010Redist-x86
winget install Microsoft.VC++2010Redist-x64
winget install Microsoft.VC++2008Redist-x86
winget install Microsoft.VC++2008Redist-x64
winget install Microsoft.VC++2005Redist-x86
winget install Microsoft.VC++2005Redist-x64
```
