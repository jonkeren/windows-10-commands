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

### Exiftool show all available EXIF tags of a file
`exiftool -G1 -a -s <filename>`

### Exiftool Write all available EXIF data from .mp4 files to corresponding XMP files
`exiftool -v -v -r -overwrite_original -ext mp4 -tagsfromfile @ -all:all -xmp:all -exif:all -iptc:all -n -srcfile %d%f.xmp -r .` 

### Exiftool write all available date fields in EXIF data to first 15 characters of the file name (f. ex. useful for files that are named like 20200503-134367.mp4), for .movs and .mp4s:
`exiftool -overwrite_original "-datetimeoriginal<${filename;$_=substr($_,0,15)}" "-createdate<${filename;$_=substr($_,0,15)}" "-FileCreateDate<${filename;$_=substr($_,0,15)}" "-FileModifyDate<${filename;$_=substr($_,0,15)}" "-TrackCreateDate<${filename;$_=substr($_,0,15)}" "-MediaCreateDate<${filename;$_=substr($_,0,15)}" "-MetaDataDate<${filename;$_=substr($_,0,15)}" "-MediaModifyDate<${filename;$_=substr($_,0,15)}" "-TrackModifyDate<${filename;$_=substr($_,0,15)}" "-ModifyDate<${filename;$_=substr($_,0,15)}" -ext mov -ext mp4 .`

### Exiftool write all available date fields in EXIF data to first 15 characters of the file name (f. ex. useful for files that are named like 20200503-134367.jpg), for .jpgs:
`exiftool -v -overwrite_original "-datetimeoriginal<${filename;$_=substr($_,0,15)}" "-createdate<${filename;$_=substr($_,0,15)}" "-FileCreateDate<${filename;$_=substr($_,0,15)}" "-FileModifyDate<${filename;$_=substr($_,0,15)}" "-MetaDataDate<${filename;$_=substr($_,0,15)}" "-ModifyDate<${filename;$_=substr($_,0,15)}"  -ext jpg .`

### Exiftool Write all (incl. GPS location) tags FROM .mp4 files TO corresponding XMP files:
`exiftool -v -v -ext mp4 -overwrite_original -tagsfromfile %d%f.mp4 -all:all %d%f.xmp .`

### Exiftool move all files to a directory structure "2020\05\03", without renaming the files themselves:
`exiftool -v -ext jpg -ext mp4 "-Directory<CreateDate" -d %Y\%m\%d\  .`

### Exiftool move all files to a directory structure "2020\05\03", AND rename the files to format "20200503-134367.jpg" (Year-Month-Day--Hour-Minute-Second):
`exiftool -v -r -d %Y\%m\%d\%Y%m%d-%H%M%S%%-c.%%e "-filename<CreateDate" .`

### Exiftool write current file name to Title and Comment EXIF fields:
`exiftool -r -overwrite_original "-xpcomment<${filename" "-comment<${filename" "-title<${filename" "-xptitle<${filename" .`

### Exiftool find all photos without GPS location tag:
`exiftool -p "$directory/$filename" -ext jpg -q -q -r -if "not $gpslatitude" .`

### Exiftool find all photos Without "createdate" EXIF tag:
`exiftool -p "$directory/$filename" -r -if "(not $createdate)" .`

### Exiftool find all photos Without "datetimeoriginal" EXIF tag:
`exiftool -p "$directory/$filename" -r -if "(not $datetimeoriginal)" .`

### Exiftool find all photos Without any date EXIF tag:
`exiftool -p "$directory/$filename" -r -if "(not $datetimeoriginal or $createdate)" .`

### Exiftool remove all makernotes:
`exiftool -overwrite_original -makernotes= .`

### Exiftool import all image data from JSON files (from Google Takeout), and write to EXIF data of corresponding photos:
`exiftool -v -r -d %s -tagsfromfile "%d/%F.json" "-GPSAltitude<GeoDataAltitude" "-GPSLatitude<GeoDataLatitude" "-GPSLatitudeRef<GeoDataLatitude" "-GPSLongitude<GeoDataLongitude" "-GPSLongitudeRef<GeoDataLongitude" "-ModifyDate<PhotoTakenTimeTimestamp" "-CreateDate<PhotoTakenTimeTimestamp" "-DateTimeOriginal<PhotoTakenTimeTimestamp" -ext jpg -overwrite_original`

### Exiftool find all photos that have NO Microsoft Face tag but HAVE an XMP-MWG Face tag, and add a keyword to those:
`exiftool -r -ext jpg -overwrite_original -m -v -if "($RegionName) and (not $RegionRectangle)" -Keywords+="Has-MS-Face-but-no-XMP-face" .`

### Exiftool create a .txt file with all photos, and listing who is on which photo (face tags):
`exiftool -T -Directory -Filename  -RegionPersonDisplayName -r -ext jpg . > PeopleTags.txt`

### Exiftool sort photos to subfolders of Camera make and camera model
`exiftool -r -v -v -ext jpg "-filename<[YOUR-TARGET-DIR-HERE]\${make;} ${model;}\%f.%e" .`

### SFC / DISM commands
`sfc /scannow`
`Dism.exe /Online /Cleanup-Image /CheckHealth`
`Dism.exe /Online /Cleanup-Image /RestoreHealth`
`Dism.exe /online /Cleanup-Image /StartComponentCleanup`
`Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase'



