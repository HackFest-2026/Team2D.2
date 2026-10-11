# Re-build and clean everything
Write-Host "Resetting database and sandbox..."
docker exec hackfest-backend-1 python -c "from database import SessionLocal, Base, engine; import models; Base.metadata.drop_all(bind=engine); Base.metadata.create_all(bind=engine);"
if (Test-Path $PSScriptRoot\..\vault) { Remove-Item -Recurse -Force $PSScriptRoot\..\vault }
Set-Location $PSScriptRoot\..\simulator
..\.venv\Scripts\python.exe simulate.py --reseed
Set-Location $PSScriptRoot\..

Write-Host "Starting agent..."
Start-Process -NoNewWindow -FilePath "$PSScriptRoot\..\.venv\Scripts\python.exe" -ArgumentList "-u main.py --run-id m4b" -WorkingDirectory "$PSScriptRoot\..\agent" -RedirectStandardOutput "$PSScriptRoot\..\agent_output.log" -RedirectStandardError "$PSScriptRoot\..\agent_error.log" -PassThru | Set-Variable agent_proc
Start-Sleep -Seconds 5

Write-Host "--- TEST 1 & 2: Analyst path & Vault Poisoning ---"
Set-Location $PSScriptRoot\..\simulator
Start-Process -NoNewWindow -FilePath "$PSScriptRoot\..\.venv\Scripts\python.exe" -ArgumentList "-u simulate.py --profile slow-and-low --run-id m4b_1" -WorkingDirectory "$PSScriptRoot\..\simulator" -PassThru | Set-Variable sim_proc
Set-Location $PSScriptRoot\..

# Wait for 25 seconds
Write-Host "Waiting 25 seconds..."
Start-Sleep -Seconds 25

# Fetch incident
$inc_json = curl.exe -s http://127.0.0.1:8000/api/incidents -H "x-agent-token: $env:AGENT_TOKEN"
Write-Host "Incidents:"
$inc_json

Stop-Process -Id $agent_proc.Id -Force
Write-Host "Agent output:"
cat $PSScriptRoot\..\agent_output.log | Select-Object -Last 10
