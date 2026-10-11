### reset_demo.ps1 — one-command reset: stop tracked processes, truncate DB,
### wipe sandbox+vault+logs, reseed, wait for backend, start agent, print READY.
$ErrorActionPreference = "Stop"
$pidFile = "$PSScriptRoot\.demo_pids"

# 1. Stop only the processes we previously started (tracked by PID file)
if (Test-Path $pidFile) {
    $pids = Get-Content $pidFile
    foreach ($procId in $pids) {
        $procId = $procId.Trim()
        if ($procId -and $procId -match '^\d+$') {
            try {
                $p = Get-Process -Id ([int]$procId) -ErrorAction SilentlyContinue
                if ($p) {
                    Stop-Process -Id ([int]$procId) -Force -ErrorAction SilentlyContinue
                    Write-Host "Stopped PID $procId ($($p.ProcessName))"
                }
            } catch {
                # Process already gone
            }
        }
    }
    Remove-Item $pidFile -Force
}

# 2. Truncate the DB
Write-Host "Truncating database..."
docker exec hackfest-db-1 psql -U threatshield -c "TRUNCATE incidents, events, alert_reasons, actions RESTART IDENTITY CASCADE;" 2>$null

# 3. Wipe and reseed the sandbox
Write-Host "Wiping and reseeding sandbox..."
& "$PSScriptRoot\.venv\Scripts\python.exe" -u "$PSScriptRoot\simulator\seed.py"

# 4. Clear the vault
$vaultPath = "$PSScriptRoot\vault"
if (Test-Path $vaultPath) {
    Remove-Item -Recurse -Force $vaultPath
}
New-Item -ItemType Directory -Path $vaultPath -Force | Out-Null
Write-Host "Vault cleared."

# 5. Clear logs
Get-ChildItem "$PSScriptRoot\*.log" -ErrorAction SilentlyContinue | Remove-Item -Force
Write-Host "Logs cleared."

# 6. Wait for backend to answer
Write-Host "Waiting for backend..."
$maxWait = 30
$waited = 0
while ($waited -lt $maxWait) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:8000/api/incidents" -Headers @{"x-agent-token"=$env:AGENT_TOKEN} -UseBasicParsing -TimeoutSec 2
        if ($r.StatusCode -eq 200) { break }
    } catch {}
    Start-Sleep -Seconds 1
    $waited++
}
if ($waited -ge $maxWait) {
    Write-Host "ERROR: Backend did not respond within $maxWait seconds." -ForegroundColor Red
    exit 1
}
Write-Host "Backend is up."

# 7. Start the agent in a new window, record its PID
$agentProc = Start-Process -FilePath "$PSScriptRoot\.venv\Scripts\python.exe" `
    -ArgumentList "-u", "$PSScriptRoot\agent\main.py", "--run-id", "demo" `
    -WorkingDirectory "$PSScriptRoot\agent" `
    -PassThru -WindowStyle Normal
$agentProc.Id | Out-File $pidFile -Encoding ascii

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  READY  (Agent PID: $($agentProc.Id))" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Run demo_attack.ps1 to start a simulated attack."
