# Reset backend db first to avoid noise
docker compose exec backend python -c "from database import SessionLocal, Base, engine; import models; Base.metadata.drop_all(bind=engine); Base.metadata.create_all(bind=engine);"

# Reseed sandbox
Set-Location $PSScriptRoot\..\simulator
..\.venv\Scripts\python.exe simulate.py --reseed
Set-Location $PSScriptRoot\..

# Start agent in background
Write-Host "Starting agent..."
Start-Process -NoNewWindow -FilePath "..\.venv\Scripts\python.exe" -ArgumentList "-u main.py --run-id agent_manifest_test" -WorkingDirectory "$PSScriptRoot\..\agent" -RedirectStandardOutput "$PSScriptRoot\..\agent_output.log" -RedirectStandardError "$PSScriptRoot\..\agent_output.log" -PassThru | Set-Variable agent_proc

Start-Sleep -Seconds 2

# Run simulator
Write-Host "Starting simulator..."
Set-Location $PSScriptRoot\..\simulator
..\.venv\Scripts\python.exe simulate.py --profile fast --run-id manifest_test
Set-Location $PSScriptRoot\..

Write-Host "Simulator exited."
Start-Sleep -Seconds 2

# Kill agent
Stop-Process -Id $agent_proc.Id -Force

Write-Host "--- Manifest ---"
Get-Content $PSScriptRoot\..\simulator\manifest.json

Write-Host "--- Sandbox Baseline (First 5 lines) ---"
Get-Content $PSScriptRoot\..\simulator\sandbox_baseline.json | Select-Object -First 5
$baseline = Get-Content $PSScriptRoot\..\simulator\sandbox_baseline.json | ConvertFrom-Json
$count = ($baseline.PSObject.Properties | Measure-Object).Count
Write-Host "Baseline Entry Count: $count"

Write-Host "--- Eval Output ---"
Set-Location $PSScriptRoot\..\eval
..\.venv\Scripts\python.exe check_containment.py manifest_test
Set-Location $PSScriptRoot\..
