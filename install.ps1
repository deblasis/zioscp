# zioscp installer for native Windows (PowerShell).
#
#   irm https://raw.githubusercontent.com/deblasis/zioscp/master/install.ps1 | iex
#
# Downloads the prebuilt Windows binary from the latest release, extracts it,
# installs it to %LOCALAPPDATA%\zioscp, and adds that to the user PATH.
#Requires -Version 5
param([string]$Dest = "$env:LOCALAPPDATA\zioscp")

$ErrorActionPreference = 'Stop'
$repo = 'deblasis/zioscp'

$rel = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
$tag = $rel.tag_name
$asset = "zioscp-$tag-x86_64-windows-gnu.zip"
$url = "https://github.com/$repo/releases/download/$tag/$asset"
Write-Host "zioscp: downloading $asset"

$zip = Join-Path $env:TEMP $asset
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
$extract = Join-Path $env:TEMP "zioscp-extract"
if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $extract -Force

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$exe = Get-ChildItem -Path $extract -Filter "zioscp.exe" -Recurse | Select-Object -First 1
# Clear the Mark-of-the-Web so SmartScreen does not gate the first run on a
# clean machine. (This does NOT affect antivirus false positives, which are a
# separate, known issue with unsigned static binaries.)
Unblock-File -Path $exe.FullName -ErrorAction SilentlyContinue
Move-Item $exe.FullName (Join-Path $Dest "zioscp.exe") -Force
Remove-Item $zip, $extract -Recurse -Force

# Add to the user PATH if not already there.
$path = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($path -and ($path -split ';') -notcontains $Dest) {
    [Environment]::SetEnvironmentVariable('Path', "$path;$Dest", 'User')
    Write-Host "zioscp: added $Dest to your PATH (open a new terminal to use it)"
} else {
    Write-Host "zioscp: $Dest already on PATH"
}
Write-Host "zioscp: installed $tag to $(Join-Path $Dest 'zioscp.exe')"
& (Join-Path $Dest 'zioscp.exe') --version
