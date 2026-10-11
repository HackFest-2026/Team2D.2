param(
    [int]$Fast = 10,
    [int]$Slow = 5,
    [int]$Benign = 10
)
$ErrorActionPreference = "Stop"
$api = "http://127.0.0.1:8000/api"
$token = $env:AGENT_TOKEN
$headers = @{"x-agent-token"=$token}

$numFast = $Fast
$numSlow = $Slow
$numBenign = $Benign

$results = @()

function Get-Incident {
    param($runId)
    $res = Invoke-WebRequest -Uri "$api/incidents" -Headers $headers -UseBasicParsing -ErrorAction SilentlyContinue
    if ($res.StatusCode -eq 200) {
        $incidents = $res.Content | ConvertFrom-Json
        foreach ($inc in $incidents) {
            $cmd = $inc.cmdline -join " "
            if ($cmd -match $runId) {
                return $inc
            }
        }
    }
    return $null
}

function Run-Trial {
    param($profile, $trialId)
    Write-Host "Running trial: $trialId ($profile)"
    
    # 1. Reset Demo
    & "$PSScriptRoot\..\reset_demo.ps1" | Out-Null
    Start-Sleep -Seconds 5
    
    $simProc = $null
    
    if ($profile -eq "benign") {
        try {
            & "$PSScriptRoot\..\run_benign.ps1" | Out-Null
        } catch {
            Write-Host "Warning: benign workload threw an error, continuing."
        }
        
        $res = Invoke-WebRequest -Uri "$api/incidents" -Headers $headers -UseBasicParsing
        $incidents = $res.Content | ConvertFrom-Json
        $count = $incidents.Count
        $maxScore = 0
        $finalStatus = "N/A"
        if ($count -gt 0) {
            $maxInc = $incidents | Sort-Object max_score -Descending | Select-Object -First 1
            $maxScore = $maxInc.max_score
            $finalStatus = $maxInc.status
        }
        
        $script:results += [PSCustomObject]@{
            Trial = $trialId
            Profile = $profile
            DetectDelayS = $null
            FilesLost = 0
            ContainedAfterS = $null
            FinalStatus = $finalStatus
            VerifyRestore = "N/A"
            MaxScore = $maxScore
            IncidentCount = $count
        }
        return
    }

    # Malicious Trial
    $simProc = Start-Process -FilePath "$PSScriptRoot\..\.venv\Scripts\python.exe" `
        -ArgumentList "-u", "simulate.py", "--profile", $profile, "--run-id", $trialId `
        -WorkingDirectory "$PSScriptRoot\..\simulator" `
        -PassThru -WindowStyle Hidden
        
    $pidFile = "$PSScriptRoot\..\.demo_pids"
    $simProc.Id | Out-File $pidFile -Encoding ascii -Append
    
    $waited = 0
    $timeout = 60
    $finalInc = $null
    $terminateSent = $false
    
    while ($waited -lt $timeout) {
        Start-Sleep -Seconds 1
        $waited++
        
        $inc = Get-Incident -runId $trialId
        if ($inc) {
            $finalInc = $inc
            if ($profile -eq "slow-and-low" -and $inc.status -eq "Suspended" -and -not $terminateSent) {
                Write-Host "  - Sent terminate action for slow-and-low"
                $body = @{type="terminate"} | ConvertTo-Json
                Invoke-WebRequest -Uri "$api/incidents/$($inc.id)/actions" -Method Post -Headers (@{"x-agent-token"=$token; "Content-Type"="application/json"}) -Body $body -UseBasicParsing | Out-Null
                $terminateSent = $true
            }
            if ($inc.status -eq "Restored" -or $inc.status -eq "Failed") {
                break
            }
        }
    }
    
    # Wait a moment for any filesystem stabilization
    Start-Sleep -Seconds 2
    
    # Check Manifest
    $manifestPath = "$PSScriptRoot\..\simulator\manifest.json"
    $filesLost = 0
    $firstWrite = 0
    if (Test-Path $manifestPath) {
        $man = Get-Content $manifestPath -Raw | ConvertFrom-Json
        $filesLost = $man.files_encrypted
        $firstWrite = $man.first_malicious_write_time
    }
    
    # Check Restore
    $verifyStr = & "$PSScriptRoot\..\.venv\Scripts\python.exe" "$PSScriptRoot\verify_restore.py"
    $verify = if ($verifyStr -match "PASS") { "PASS" } else { "FAIL" }
    
    $detectDelay = $null
    $containedS = $null
    $maxScore = 0
    $status = "Missed"
    
    if ($finalInc) {
        $maxScore = $finalInc.max_score
        $status = $finalInc.status
        if ($finalInc.start_time -and $firstWrite -gt 0) {
            $stString = $finalInc.start_time
            if (-not $stString.EndsWith("Z")) { $stString += "Z" }
            $unixTime = [DateTimeOffset]::Parse($stString).ToUnixTimeMilliseconds() / 1000.0
            $detectDelay = [math]::Round($unixTime - $firstWrite, 2)
        }
        if ($finalInc.contained_after_ms) {
            $containedS = [math]::Round($finalInc.contained_after_ms / 1000.0, 2)
        }
    }
    
    $script:results += [PSCustomObject]@{
        Trial = $trialId
        Profile = $profile
        DetectDelayS = $detectDelay
        FilesLost = $filesLost
        ContainedAfterS = $containedS
        FinalStatus = $status
        VerifyRestore = $verify
        MaxScore = $maxScore
        IncidentCount = if ($finalInc) { 1 } else { 0 }
    }
}

for ($i = 1; $i -le $numFast; $i++) { Run-Trial "fast" "fast_$i" }
for ($i = 1; $i -le $numSlow; $i++) { Run-Trial "slow-and-low" "slow_$i" }
for ($i = 1; $i -le $numBenign; $i++) { Run-Trial "benign" "benign_$i" }

$results | Export-Csv -Path "$PSScriptRoot\results.csv" -NoTypeInformation

# Summary
$malicious = $results | Where-Object { $_.Profile -ne "benign" }
$detected = $malicious | Where-Object { $_.IncidentCount -gt 0 }
$detectionRate = if ($malicious.Count -gt 0) { [math]::Round($detected.Count / $malicious.Count * 100, 1) } else { 0 }

$benignRuns = $results | Where-Object { $_.Profile -eq "benign" }
$fps = $benignRuns | Where-Object { $_.FinalStatus -match "Suspend|Terminate" }
$alerts = $benignRuns | Where-Object { $_.FinalStatus -match "Alert" }
$fpRate = if ($benignRuns.Count -gt 0) { [math]::Round($fps.Count / $benignRuns.Count * 100, 1) } else { 0 }
$alertRate = if ($benignRuns.Count -gt 0) { [math]::Round($alerts.Count / $benignRuns.Count * 100, 1) } else { 0 }

$delays = $detected | Where-Object { $_.DetectDelayS -ne $null } | Select-Object -ExpandProperty DetectDelayS
$meanDelay = if ($delays.Count -gt 0) { [math]::Round(($delays | Measure-Object -Average).Average, 2) } else { 0 }
$maxDelay = if ($delays.Count -gt 0) { [math]::Round(($delays | Measure-Object -Maximum).Maximum, 2) } else { 0 }

$lost = $malicious | Select-Object -ExpandProperty FilesLost
$meanLost = if ($lost.Count -gt 0) { [math]::Round(($lost | Measure-Object -Average).Average, 1) } else { 0 }

$restoredCount = ($malicious | Where-Object { $_.VerifyRestore -eq "PASS" }).Count
$restoreRate = if ($malicious.Count -gt 0) { [math]::Round($restoredCount / $malicious.Count * 100, 1) } else { 0 }

Write-Host ""
Write-Host "=== SUMMARY ==="
Write-Host "Detection Rate:   $detectionRate %"
Write-Host "False Pos Rate:   $fpRate %"
Write-Host "Benign Alert Rt:  $alertRate %"
Write-Host "Mean Detect Dly:  $meanDelay s (Max: $maxDelay s)"
Write-Host "Mean Files Lost:  $meanLost"
Write-Host "Restore PASS:     $restoreRate %"
Write-Host "==============="
