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
