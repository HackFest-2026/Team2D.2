$ErrorActionPreference = "Stop"

if (Test-Path $PSScriptRoot\..\logs\m2_B.log*) {
    Remove-Item $PSScriptRoot\..\logs\m2_B.log* -Force
}

function Seed {
    cd $PSScriptRoot\..\simulator
    $PSScriptRoot\..\.venv\Scripts\python.exe seed.py
}

function RunSimulator($profile) {
    cd $PSScriptRoot\..\simulator
    if (Test-Path manifest.json) { Remove-Item manifest.json -Force }
    $PSScriptRoot\..\.venv\Scripts\python.exe run_sim.py $profile
    $pidStr = Get-Content sim_pid.txt
    return [int]$pidStr
}

function RunAgent($args, $logFile) {
    cd $PSScriptRoot\..\agent
    $job = Start-Process $PSScriptRoot\..\.venv\Scripts\python.exe -ArgumentList "main.py $args" -RedirectStandardOutput "$PSScriptRoot\..\logs\$logFile" -RedirectStandardError "$PSScriptRoot\..\logs\${logFile}.err" -PassThru -WindowStyle Hidden
    return $job
}

Write-Host "Running Test B..."
Seed
$agent = RunAgent "--dry-run" "m2_B.log"
Start-Sleep -Seconds 2
$simId = RunSimulator "slow-and-low"
Start-Sleep -Seconds 8

try {
    $PSScriptRoot\..\.venv\Scripts\python.exe -c "import psutil; p=psutil.Process($simId); p.resume(); p.resume()"
} catch {}
Stop-Process -Id $simId -Force -ErrorAction SilentlyContinue

try {
    $PSScriptRoot\..\.venv\Scripts\python.exe -c "import psutil; p=psutil.Process($($agent.Id)); p.resume(); p.resume()"
} catch {}
Stop-Process -Id $agent.Id -Force -ErrorAction SilentlyContinue

Start-Sleep -Seconds 1
Write-Host "Test B finished."
