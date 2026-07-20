$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Tools = Join-Path $ProjectRoot "tools"
$Evidence = Join-Path $ProjectRoot "evidence"
$NginxZip = Join-Path $Tools "nginx-1.30.4.zip"
$NginxRoot = Join-Path $Tools "nginx-1.30.4"
$NginxExe = Join-Path $NginxRoot "nginx.exe"
$LabConfig = Join-Path $ProjectRoot "lab\nginx-windows.conf"
$Scanner = Join-Path $ProjectRoot "scripts\audit_nginx_map_risk.py"
$Out = Join-Path $Evidence "windows-nginx-validation-output.txt"

New-Item -ItemType Directory -Force -Path $Tools, $Evidence | Out-Null

function Invoke-ProcessCapture {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList
    )
    $stdout = New-TemporaryFile
    $stderr = New-TemporaryFile
    try {
        $proc = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdout.FullName -RedirectStandardError $stderr.FullName
        $outText = Get-Content -LiteralPath $stdout.FullName -Raw -ErrorAction SilentlyContinue
        $errText = Get-Content -LiteralPath $stderr.FullName -Raw -ErrorAction SilentlyContinue
        (($outText, $errText) -join "").Trim()
    }
    finally {
        Remove-Item -LiteralPath $stdout.FullName, $stderr.FullName -Force -ErrorAction SilentlyContinue
    }
}

if (!(Test-Path $NginxExe)) {
    Invoke-WebRequest -Uri "https://nginx.org/download/nginx-1.30.4.zip" -OutFile $NginxZip
    Expand-Archive -LiteralPath $NginxZip -DestinationPath $Tools -Force
}

$commands = @(
    "Source: https://nginx.org/en/download.html",
    "NGINX binary: $NginxExe",
    "",
    "== nginx -v ==",
    (Invoke-ProcessCapture $NginxExe @("-v")),
    "",
    "== nginx -t -c lab config ==",
    (Invoke-ProcessCapture $NginxExe @("-t", "-p", $NginxRoot, "-c", $LabConfig)),
    "",
    "== scanner against lab config ==",
    (Invoke-ProcessCapture "python" @($Scanner, $LabConfig))
)

$commands -join [Environment]::NewLine | Tee-Object -FilePath $Out

Write-Host ""
Write-Host "Evidence saved to $Out"
