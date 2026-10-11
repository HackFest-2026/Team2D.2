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

Write-Host "--- TEST 3: Benign Workloads ---"
.\run_benign.ps1
Write-Host "Incidents after benign workloads (should be none or score < 70):"
curl.exe -s http://127.0.0.1:8000/api/incidents -H "x-agent-token: $env:AGENT_TOKEN"
Write-Host "Vault frozen status in agent log:"
Select-String -Path $PSScriptRoot\..\agent_output.log -Pattern "frozen" -Quiet

Write-Host "--- TEST 1 & 2: Analyst path & Vault Poisoning ---"
Set-Location $PSScriptRoot\..\simulator
Start-Process -NoNewWindow -FilePath "$PSScriptRoot\..\.venv\Scripts\python.exe" -ArgumentList "-u simulate.py --profile slow-and-low --run-id m4b_1" -WorkingDirectory "$PSScriptRoot\..\simulator" -PassThru | Set-Variable sim_proc
Set-Location $PSScriptRoot\..

# Wait for 2 backup intervals (25 seconds)
Write-Host "Waiting 25 seconds for simulator to reach suspend tier and span 2 backup intervals..."
Start-Sleep -Seconds 25

# Helper for stats
function Print-Stats ($stepName) {
    Write-Host "--- Stats: $stepName ---"
    if (Test-Path $PSScriptRoot\..\simulator\manifest.json) {
        $man = Get-Content $PSScriptRoot\..\simulator\manifest.json | ConvertFrom-Json
        Write-Host "Manifest files_encrypted: $($man.files_encrypted)"
    }
    $locked = (Get-ChildItem $PSScriptRoot\..\sandbox -Filter "*.locked" -Recurse | Measure-Object).Count
    Write-Host ".locked files in sandbox: $locked"
    $fullJson = docker exec hackfest-backend-1 python -c "import urllib.request, json; print(json.dumps(json.loads(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/incidents/$inc_id', headers={'x-agent-token':$env:AGENT_TOKEN})).read().decode())['incident'], indent=2))"
    Write-Host "Incident JSON:"
    Write-Host $fullJson
}

# Fetch incident
$inc_id = docker exec hackfest-backend-1 python -c "import urllib.request, json; print(json.loads(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/api/incidents', headers={'x-agent-token':$env:AGENT_TOKEN})).read().decode())[-1]['id'])"
Write-Host "Incident ID: $inc_id"
Print-Stats "Before Resume (Suspended)"

# Vault poisoning check
Write-Host "Vault version count per file:"
if (Test-Path $PSScriptRoot\..\vault\index.json) {
    (Get-ChildItem $PSScriptRoot\..\vault\index.json | Get-Content | ConvertFrom-Json).PSObject.Properties | Select-Object Name, @{Name="VersionCount";Expression={$_.Value.Count}} | Select-Object -First 5
} else {
    Write-Host "index.json not found."
}

# Test manual resume
Write-Host "Triggering manual RESUME..."
$headers = @{"Content-Type" = "application/json"; "x-agent-token" = $env:AGENT_TOKEN}
$body = '{"type":"resume"}'
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/incidents/$inc_id/actions" -Method Post -Headers $headers -Body $body | Out-Null
Start-Sleep -Seconds 10
Print-Stats "After Resume (Resumed)"

# Test manual terminate
Write-Host "Triggering manual TERMINATE..."
$body = '{"type":"terminate"}'
try {
    Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/incidents/$inc_id/actions" -Method Post -Headers $headers -Body $body | Out-Null
} catch {
    Write-Host "Caught expected exception during manual terminate: $($_.Exception.Message)"
}
Start-Sleep -Seconds 10
Print-Stats "After Terminate (Terminated)"

# Test manual restore
Write-Host "Wait 5s then print stats before restore..."
Start-Sleep -Seconds 5
Print-Stats "Before Restore"

# The restore was likely auto-enqueued. But we also test deduplication.
Write-Host "Triggering manual RESTORE (Deduplication Test)..."
$body = '{"type":"restore"}'
try {
    Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/incidents/$inc_id/actions" -Method Post -Headers $headers -Body $body | Out-Null
} catch {
    Write-Host "Caught expected exception during deduplication: $($_.Exception.Message)"
}
Start-Sleep -Seconds 15
Print-Stats "After Restore (Restored)"

Write-Host "Stopping agent..."
Stop-Process -Id $agent_proc.Id -Force

Write-Host "--- Verify Restore ---"
Set-Location $PSScriptRoot\..\eval
..\.venv\Scripts\python.exe verify_restore.py
Set-Location $PSScriptRoot\..

Write-Host "--- Agent log freeze line ---"
Select-String -Path $PSScriptRoot\..\agent_output.log -Pattern "frozen" | Select-Object -First 3
