### demo_attack.ps1 — run the fast-profile simulator with run-id demo_<timestamp>
$ErrorActionPreference = "Stop"
$pidFile = "$PSScriptRoot\.demo_pids"
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$runId = "demo_$ts"

Write-Host "Starting simulated attack: run-id=$runId profile=fast"

$simProc = Start-Process -FilePath "$PSScriptRoot\.venv\Scripts\python.exe" `
    -ArgumentList "-u", "simulate.py", "--profile", "fast", "--run-id", $runId `
    -WorkingDirectory "$PSScriptRoot\simulator" `
    -PassThru -WindowStyle Normal

# Append simulator PID to the tracking file
$simProc.Id | Out-File $pidFile -Encoding ascii -Append

Write-Host "Simulator PID: $($simProc.Id), run-id: $runId"
Write-Host "Watch the agent window for detection and containment."
