# Restart backend to load new models.py
docker restart hackfest-backend-1
Start-Sleep -Seconds 3

# Reset backend db and tables
docker exec hackfest-backend-1 python -c "from database import SessionLocal, Base, engine; import models; Base.metadata.drop_all(bind=engine); Base.metadata.create_all(bind=engine);"

# Clean up vault
if (Test-Path $PSScriptRoot\..\vault) {
    Remove-Item -Recurse -Force $PSScriptRoot\..\vault
}

# Reseed sandbox
Write-Host "Reseeding sandbox..."
Set-Location $PSScriptRoot\..\simulator
..\.venv\Scripts\python.exe simulate.py --reseed
Write-Host "Locked files after reseed:"
(Get-ChildItem $PSScriptRoot\..\sandbox -Recurse -File -Filter *.locked | Measure-Object).Count
Write-Host "Total files after reseed:"
(Get-ChildItem $PSScriptRoot\..\sandbox -Recurse -File | Measure-Object).Count
Set-Location $PSScriptRoot\..

# Start agent in background
Write-Host "Starting agent..."
Start-Process -NoNewWindow -FilePath "$PSScriptRoot\..\.venv\Scripts\python.exe" -ArgumentList "-u main.py --run-id m4a_agent" -WorkingDirectory "$PSScriptRoot\..\agent" -RedirectStandardOutput "$PSScriptRoot\..\agent_output.log" -RedirectStandardError "$PSScriptRoot\..\agent_error.log" -PassThru | Set-Variable agent_proc

Start-Sleep -Seconds 5

# Run simulator
Write-Host "Starting simulator..."
Set-Location $PSScriptRoot\..\simulator
..\.venv\Scripts\python.exe simulate.py --profile fast --run-id m4a_1
Set-Location $PSScriptRoot\..

Write-Host "Simulator exited. Waiting for restore to finish..."
Start-Sleep -Seconds 15

# Kill agent
Stop-Process -Id $agent_proc.Id -Force

Write-Host "--- Agent Log ---"
Select-String -Path $PSScriptRoot\..\agent_output.log -Pattern "terminate|restore"

Write-Host "--- Actions Table ---"
docker exec hackfest-db-1 psql -U threatshield -c "SELECT id, type, status, result FROM actions;"

Write-Host "--- Incident JSON ---"
curl.exe -s http://127.0.0.1:8000/api/incidents -H "x-agent-token: $env:AGENT_TOKEN" | ConvertFrom-Json | Select-Object id, status, restored_count | ConvertTo-Json

Write-Host "--- Vault Directory ---"
Get-ChildItem $PSScriptRoot\..\vault -Recurse | Select-Object Name | Select-Object -First 10

Write-Host "--- Verify Restore ---"
Set-Location $PSScriptRoot\..\eval
..\.venv\Scripts\python.exe verify_restore.py
Set-Location $PSScriptRoot\..
