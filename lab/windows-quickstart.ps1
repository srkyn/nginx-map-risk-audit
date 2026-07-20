$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Scanner = Join-Path $ProjectRoot "scripts\audit_nginx_map_risk.py"
$Samples = Join-Path $ProjectRoot "samples"
$Evidence = Join-Path $ProjectRoot "evidence\scanner-sample-output.txt"

python $Scanner $Samples | Tee-Object -FilePath $Evidence

Write-Host ""
Write-Host "Evidence saved to $Evidence"
