# start_client.ps1
# Helper script to launch the FRP client on Windows.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host "Starting DecoyOps FRP Client Tunnel..." -ForegroundColor Cyan
Write-Host "Make sure you have edited frpc.toml with your VPS IP!" -ForegroundColor Yellow

.\frpc.exe -c .\frpc.toml

if ($LASTEXITCODE -ne 0) {
    Write-Host "FRP Client exited with code $LASTEXITCODE" -ForegroundColor Red
    Pause
}
