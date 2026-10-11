# Benign Workload Test
Write-Host "Running benign workloads..."

# 1. Zip a folder inside the sandbox
Write-Host "1. Zipping a folder inside the sandbox..."
if (Test-Path "$PSScriptRoot\..\sandbox\archive.zip") { Remove-Item "$PSScriptRoot\..\sandbox\archive.zip" }
Compress-Archive -Path "$PSScriptRoot\..\sandbox\*" -DestinationPath "$PSScriptRoot\..\sandbox\archive.zip" -Force

Start-Sleep -Seconds 10

# 2. Copy 100 files
Write-Host "2. Copying 100 files..."
$dest = "$PSScriptRoot\..\sandbox\benign_copies"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$files = Get-ChildItem "$PSScriptRoot\..\sandbox" -File | Where-Object { $_.Name -notmatch "^\." } | Select-Object -First 10
for ($i = 0; $i -lt 10; $i++) {
    foreach ($file in $files) {
        Copy-Item $file.FullName "$dest\$($file.Name)_copy_$i" -Force
    }
}

Start-Sleep -Seconds 10

# 3. Rename churn
Write-Host "3. Rename churn..."
for ($i = 0; $i -lt 50; $i++) {
    $target = "$dest\churn_$i.txt"
    Set-Content -Path $target -Value "Hello World $i"
    Start-Sleep -Milliseconds 50
    Rename-Item -Path $target -NewName "churn_renamed_$i.txt"
}

Start-Sleep -Seconds 10
Write-Host "Done benign."
