
# Inspired by question of Stefan Boutsen https://superuser.com/users/2759400/stefan-boutsen
# File Explorer is slow when traversing files synced with OneDrive on Windows 11
# https://superuser.com/questions/1891413/file-explorer-is-slow-when-traversing-files-synced-with-onedrive-on-windows-11/1940024

# On Windows 11 Onedrive is very slow accessing through the main window Onedrive or SharePointsync'd folders. 
# Using procmon, Explorer.exe is losing 5-6 seconds doing a lot of ReqQueryKey on the HKCU\Software\Classes\ tree. 
# It boils down on changing permission to full control for the ondrivesync entries here: Computer\HKEY_CLASSES_ROOT\PackagedCom\Package\Microsoft.OneDriveSync_xxxxxxxx to the "Everyone" account. 
# No more entries logged on HKCU\Software\Classes tree. This speeds up Navigating Onedrive folders in Explorer by at least 10x. 

# This script sets the rights on those registry keys, for all keys starting with Microsoft.OneDriveSync_. Also after a reboot it persists. 
# You maybe should run this again after a new version of OneDrive is installed, and a new key (with another version number) is created. 

# Ensure the script is running with Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Please run this script as an Administrator."
    exit
}

$basePath = "HKLM:\Software\Classes\PackagedCom\Package"
$targetKeys = Get-ChildItem -Path $basePath | Where-Object { $_.PSChildName -like "Microsoft.OneDriveSync_*" }

if (-not $targetKeys) {
    Write-Host "No OneDriveSync registry keys found." -ForegroundColor Yellow
    exit
}

foreach ($key in $targetKeys) {
    $path = $key.PSPath
    Write-Host "Processing: $($key.PSChildName)" -NoNewline
    
    try {
        $acl = Get-Acl -Path $path
        
        # S-1-1-0 is the universal SID for Everyone / Iedereen
        $everyoneSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $everyoneSid, 
            "FullControl", 
            "ContainerInherit, ObjectInherit", 
            "None", 
            "Allow"
        )
        
        $acl.SetAccessRule($rule)
        Set-Acl -Path $path -AclObject $acl
        Write-Host " [Success]" -ForegroundColor Green
    }
    catch {
        Write-Host " [Failed: $_]" -ForegroundColor Red
    }
}

Write-Host "`nDone. You may want to restart OneDrive or your PC." -ForegroundColor Cyan
