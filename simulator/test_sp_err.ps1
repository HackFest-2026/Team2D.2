cd $PSScriptRoot\..\simulator
$PSScriptRoot\..\.venv\Scripts\python.exe seed.py

$sim = Start-Process $PSScriptRoot\..\.venv\Scripts\python.exe -ArgumentList "simulate.py --profile slow-and-low" -RedirectStandardError "err.txt" -RedirectStandardOutput "out.txt" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
$PSScriptRoot\..\.venv\Scripts\python.exe -c "import psutil; p=psutil.Process($($sim.Id)); print(p.io_counters())"
Stop-Process -Id $sim.Id -Force
Get-Content err.txt
Get-Content out.txt
