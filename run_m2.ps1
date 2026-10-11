$ErrorActionPreference = "Stop"

function Seed {
    cd $PSScriptRoot\..\simulator
    $PSScriptRoot\..\.venv\Scripts\python.exe seed.py
}

function RunSimulator($profile, $runId) {
    cd $PSScriptRoot\..\simulator
    if (Test-Path manifest.json) { Remove-Item manifest.json -Force }
    $PSScriptRoot\..\.venv\Scripts\python.exe run_sim.py $profile $runId
    $pidStr = Get-Content sim_pid.txt
    return [int]$pidStr
}

function RunAgent($args, $logFile, $runId) {
    cd $PSScriptRoot\..\agent
    $job = Start-Process $PSScriptRoot\..\.venv\Scripts\python.exe -ArgumentList "main.py $args --run-id $runId" -RedirectStandardOutput "$PSScriptRoot\..\logs\$logFile" -RedirectStandardError "$PSScriptRoot\..\logs\${logFile}.err" -PassThru -WindowStyle Hidden
    return $job
}

function AssertManifest($name, $runId) {
    cd $PSScriptRoot\..\simulator
    if (-not (Test-Path manifest.json)) {
        Write-Error "[$name] manifest.json does not exist!"
        return
    }
    
    $mtime = (Get-Item manifest.json).LastWriteTime
    $start = (Get-Process -Id $PID).StartTime
    if ($mtime -lt $start) {
        Write-Error "[$name] manifest.json is STALE! mtime: $mtime"
    }

    $manifest = Get-Content manifest.json -Raw | ConvertFrom-Json
    if ($manifest.run_id -ne $runId) {
        Write-Host "WARNING: [$name] manifest.json run_id mismatch! Expected: $runId, Got: $($manifest.run_id)"
    }
    
    Copy-Item manifest.json "..\logs\m2_${name}_manifest.json" -Force
}

if (Test-Path $PSScriptRoot\..\logs\m2_*.log*) {
    Remove-Item $PSScriptRoot\..\logs\m2_*.log* -Force
}
if (Test-Path $PSScriptRoot\..\logs\m2_*_manifest.json) {
    Remove-Item $PSScriptRoot\..\logs\m2_*_manifest.json -Force
}

$scenarios = @("A", "B", "C", "D", "F", "G")
foreach ($s in $scenarios) {
    $runId = [guid]::NewGuid().ToString()
    Write-Host "Running Test $s with run_id $runId..."
    Seed
    
    if ($s -eq "A") {
        $agent = RunAgent "--dry-run" "m2_A.log" $runId
        Start-Sleep -Seconds 2
        $simId = RunSimulator "fast" $runId
        Start-Sleep -Seconds 5
        AssertManifest $s $runId
    } elseif ($s -eq "B") {
        $agent = RunAgent "--dry-run" "m2_B.log" $runId
        Start-Sleep -Seconds 2
        $simId = RunSimulator "slow-and-low" $runId
        Start-Sleep -Seconds 10
        AssertManifest $s $runId
    } elseif ($s -eq "C") {
        $agent = RunAgent "--dry-run" "m2_C.log" $runId
        Start-Sleep -Seconds 2
        $simId = RunSimulator "canary-touching" $runId
        Start-Sleep -Seconds 10
        AssertManifest $s $runId
    } elseif ($s -eq "D") {
        $agent = RunAgent "--dry-run" "m2_D.log" $runId
        Start-Sleep -Seconds 2
        $simId = RunSimulator "fast" $runId
        Start-Sleep -Seconds 5
        AssertManifest $s $runId
    } elseif ($s -eq "F") {
        Write-Host "Skipping F for now as we test simulator."
        continue
    } elseif ($s -eq "G") {
        $agent = RunAgent "" "m2_G.log" $runId
        Start-Sleep -Seconds 2
        $simId = RunSimulator "canary-touching" $runId
        
        Write-Host "Test G: Waiting for agent to suspend..."
        Start-Sleep -Seconds 10
        
        Write-Host "Test G: suspend again..."
        $PSScriptRoot\..\.venv\Scripts\python.exe -c "import psutil; p=psutil.Process($simId); p.suspend()"
        
        Write-Host "Test G: resume..."
        $PSScriptRoot\..\.venv\Scripts\python.exe -c "import psutil; p=psutil.Process($simId); p.resume()"
        
        Write-Host "Test G: status..."
        $PSScriptRoot\..\.venv\Scripts\python.exe -c "import psutil; p=psutil.Process($simId); print(p.status())"
        
        Write-Host "Test G: resume..."
        $PSScriptRoot\..\.venv\Scripts\python.exe -c "import psutil; p=psutil.Process($simId); p.resume()"
        
        Write-Host "Test G: status..."
        $PSScriptRoot\..\.venv\Scripts\python.exe -c "import psutil; p=psutil.Process($simId); print(p.status())"
        
        Write-Host "Test G: waiting for simulator exit..."
        Stop-Process -Id $agent.Id -Force
        $simProc = Get-Process -Id $simId -ErrorAction SilentlyContinue
        if ($simProc) {
            $simProc.WaitForExit()
            Write-Host "Simulator exit code: $($simProc.ExitCode)"
        }
        
        AssertManifest $s $runId
    }

    try {
        $PSScriptRoot\..\.venv\Scripts\python.exe -c "import psutil; p=psutil.Process($simId); p.resume(); p.resume()"
    } catch {}
    Stop-Process -Id $simId -Force -ErrorAction SilentlyContinue

    try {
        $PSScriptRoot\..\.venv\Scripts\python.exe -c "import psutil; p=psutil.Process($($agent.Id)); p.resume(); p.resume()"
    } catch {}
    Stop-Process -Id $agent.Id -Force -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2
    Write-Host "Test $s finished."
}

Write-Host "Get-Date: $(Get-Date)"
$PSScriptRoot\..\.venv\Scripts\python.exe -c "import time; print(f'python time: {time.time()}')"
