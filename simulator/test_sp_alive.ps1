$sim = Start-Process $PSScriptRoot\..\.venv\Scripts\python.exe -ArgumentList "simulate.py --profile slow-and-low" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
Write-Host "Process Exited: $($sim.HasExited)"
if (-not $sim.HasExited) {
    Stop-Process -Id $sim.Id -Force
}
