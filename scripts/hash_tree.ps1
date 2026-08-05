[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputDirectory,

    [Parameter(Mandatory = $true)]
    [string]$OutputManifest
)

$root = (Resolve-Path -LiteralPath $InputDirectory).Path
$files = Get-ChildItem -LiteralPath $root -File -Recurse | Sort-Object FullName

$lines = foreach ($file in $files) {
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $relative = [System.IO.Path]::GetRelativePath($root, $file.FullName).Replace('\\', '/')
    "{0}  {1}  {2}" -f $hash, $file.Length, $relative
}

$lines | Set-Content -LiteralPath $OutputManifest -Encoding utf8
Write-Host "Wrote $OutputManifest"
