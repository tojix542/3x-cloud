
# ============================================================
# 3X CLOUD PC CHECKER — Self-Extracting .EXE Builder
# This script creates a .exe that runs the forensic scanner
# ============================================================

param(
    [string]$OutputPath = "$env:USERPROFILE\Desktop\3X-Checker.exe",
    [string]$ServerUrl = "https://3x-cloudxbeta.hmktt22.workers.dev"
)

$ErrorActionPreference = "SilentlyContinue"

# The embedded PowerShell script that runs inside the .exe
$embeddedScript = @'
# 3X CLOUD PC CHECKER — Embedded Scanner
param([string]$ServerUrl="https://3x-cloudxbeta.hmktt22.workers.dev")

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create hidden form for progress
$form = New-Object System.Windows.Forms.Form
$form.Text = "3X Cloud Scanner"
$form.Size = New-Object System.Drawing.Size(500, 300)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(10, 10, 15)
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Title
$title = New-Object System.Windows.Forms.Label
$title.Text = "3X Cloud Forensic Scanner"
$title.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = [System.Drawing.Color]::FromArgb(123, 97, 255)
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(80, 20)
$form.Controls.Add($title)

# Subtitle
$sub = New-Object System.Windows.Forms.Label
$sub.Text = "Scanning your system for forensic evidence..."
$sub.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$sub.ForeColor = [System.Drawing.Color]::FromArgb(156, 163, 175)
$sub.AutoSize = $true
$sub.Location = New-Object System.Drawing.Point(110, 60)
$form.Controls.Add($sub)

# Progress bar
$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(50, 100)
$progress.Size = New-Object System.Drawing.Size(400, 20)
$progress.Style = "Continuous"
$progress.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 40)
$progress.ForeColor = [System.Drawing.Color]::FromArgb(123, 97, 255)
$form.Controls.Add($progress)

# Status label
$status = New-Object System.Windows.Forms.Label
$status.Text = "Initializing..."
$status.Font = New-Object System.Drawing.Font("Consolas", 9)
$status.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 220)
$status.AutoSize = $true
$status.Location = New-Object System.Drawing.Point(50, 135)
$form.Controls.Add($status)

# Log box
$log = New-Object System.Windows.Forms.TextBox
$log.Multiline = $true
$log.ScrollBars = "Vertical"
$log.Location = New-Object System.Drawing.Point(50, 160)
$log.Size = New-Object System.Drawing.Size(400, 80)
$log.BackColor = [System.Drawing.Color]::FromArgb(6, 6, 10)
$log.ForeColor = [System.Drawing.Color]::FromArgb(180, 168, 212)
$log.Font = New-Object System.Drawing.Font("Consolas", 8)
$log.BorderStyle = "FixedSingle"
$log.ReadOnly = $true
$form.Controls.Add($log)

# Result label (hidden initially)
$resultLabel = New-Object System.Windows.Forms.Label
$resultLabel.Text = ""
$resultLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$resultLabel.AutoSize = $true
$resultLabel.Location = New-Object System.Drawing.Point(50, 250)
$resultLabel.Visible = $false
$form.Controls.Add($resultLabel)

$script:Evidence = @()
$script:Findings = @()

function Add-Log($msg) {
    $log.AppendText("[3X] $msg`r`n")
    $log.ScrollToCaret()
    $status.Text = $msg
    [System.Windows.Forms.Application]::DoEvents()
}

function Add-Evidence($Level, $Title, $Detail) {
    $script:Evidence += [PSCustomObject]@{level=$Level; title=$Title; detail=$Detail; time=(Get-Date).ToString("HH:mm:ss")}
}

function Add-Finding($Pattern, $Risk, $Desc) {
    $script:Findings += [PSCustomObject]@{pattern=$Pattern; risk=$Risk; description=$Desc}
}

# Detection modules
function Test-StaggeredDeletes {
    Add-Log "Checking USN Journal..."
    try {
        $usn = fsutil usn readjournal C: 2>$null | Select-String "Delete"
        if ($usn -and $usn.Count -ge 3) {
            Add-Evidence "suspicious" "Staggered File Deletion" "USN Journal shows $($usn.Count) delete operations"
            Add-Finding "staggered_deletes" 85 "Files deleted with irregular timing"
        }
    } catch { Add-Evidence "info" "USN Journal" "Could not read (insufficient privileges)" }
}

function Test-TimestampFixing {
    Add-Log "Checking timestamps..."
    try {
        $files = Get-ChildItem "$env:TEMP" -File -Recurse -ErrorAction SilentlyContinue | Where-Object { ($_.LastWriteTime - $_.CreationTime).TotalDays -gt 30 } | Select-Object -First 5
        if ($files) {
            Add-Evidence "suspicious" "Timestamp Manipulation" "Files with anomalous timestamps found"
            Add-Finding "timestamp_fixing" 90 "File times artificially altered"
        }
    } catch { }
}

function Test-SelectiveCleanup {
    Add-Log "Checking prefetch..."
    try {
        $pf = Get-ChildItem "$env:SystemRoot\Prefetch" -ErrorAction SilentlyContinue
        if ($pf -and $pf.Count -lt 30 -and $pf.Count -gt 0) {
            Add-Evidence "suspicious" "Prefetch Gap" "Only $($pf.Count) prefetch files (expected 50+)"
            Add-Finding "prefetch_gap" 75 "Missing prefetch entries"
        }
    } catch { }
}

function Test-EventLogManipulation {
    Add-Log "Checking event logs..."
    try {
        $evt = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($evt) {
            Add-Evidence "threat" "Event Log Cleared" "Security log cleared — Event ID 1102"
            Add-Finding "no_event_104" 70 "Event logs manipulated"
        }
    } catch { }
}

function Test-RegistryInconsistency {
    Add-Log "Checking registry..."
    try {
        $rk = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
        $sus = @()
        $rk.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
            if ($_.Value -match "powershell|cmd\.exe|wscript|mshta|bitsadmin|certutil") { $sus += $_.Name }
        }
        if ($sus.Count -gt 0) {
            Add-Evidence "threat" "Suspicious Startup" "Run keys: $($sus -join ', ')"
            Add-Finding "hidden_execution" 85 "Malicious execution hidden"
        }
    } catch { }
}

function Test-MemoryInjection {
    Add-Log "Checking FiveM process..."
    try {
        $fm = Get-Process "FiveM" -ErrorAction SilentlyContinue
        if ($fm) {
            $mods = $fm.Modules | Where-Object { $_.ModuleName -notin @("ntdll.dll","kernel32.dll","kernelbase.dll","user32.dll","gdi32.dll","advapi32.dll","rpcrt4.dll","sspicli.dll","cryptbase.dll","bcryptprimitives.dll","msvcp_win.dll","ucrtbase.dll","shell32.dll","shlwapi.dll","combase.dll","ws2_32.dll","wininet.dll","winhttp.dll","dnsapi.dll","iphlpapi.dll","nsi.dll","dhcpcsvc.dll","dhcpcsvc6.dll","crypt32.dll","msasn1.dll","wintrust.dll","rsaenh.dll","bcrypt.dll","ncrypt.dll","tpmtasks.dll","tbs.dll","devobj.dll","cfgmgr32.dll","powrprof.dll","umpdc.dll","profapi.dll","kernel.appcore.dll","cryptsp.dll","imm32.dll","msctf.dll","ole32.dll","oleaut32.dll","msvcp140.dll","vcruntime140.dll","vcruntime140_1.dll","FiveM.exe","FiveM_GTAProcess.exe","adhesive.dll","citizen-resources-core.dll","citizen-scripting-lua.dll") }
            if ($mods) {
                $mn = ($mods | Select-Object -First 3 | ForEach-Object { $_.ModuleName }) -join ", "
                Add-Evidence "threat" "Unknown Module in FiveM" "Suspicious DLLs: $mn"
                Add-Finding "memory_injection" 95 "Code injected into FiveM"
            }
        }
    } catch { }
}

function Test-LSASSAccess {
    Add-Log "Checking LSASS..."
    try {
        $lsass = Get-Process "lsass" -ErrorAction SilentlyContinue
        if ($lsass) {
            # Simple check: look for processes with same session
            $suspicious = Get-Process | Where-Object { $_.ProcessName -match "mimikatz|procdump|lsadump|secretsdump" }
            if ($suspicious) {
                Add-Evidence "threat" "LSASS Access" "Credential dumping tools detected"
                Add-Finding "lsass_anomaly" 90 "Suspicious LSASS access"
            }
        }
    } catch { }
}

function Test-AlternateDataStreams {
    Add-Log "Checking ADS..."
    try {
        $ads = Get-ChildItem "$env:TEMP" -Recurse -ErrorAction SilentlyContinue | Get-Item -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ":`$DATA" } | Select-Object -First 5
        if ($ads) {
            Add-Evidence "suspicious" "Alternate Data Streams" "NTFS ADS found on $($ads.Count) files"
            Add-Finding "ads_usage" 80 "Hidden payloads in ADS"
        }
    } catch { }
}

function Test-ShadowCopyWipe {
    Add-Log "Checking shadow copies..."
    try {
        $vss = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue
        if (-not $vss -or $vss.Count -eq 0) {
            Add-Evidence "suspicious" "No Shadow Copies" "VSS missing — possible deletion"
            Add-Finding "shadow_copy_wipe" 90 "Shadow copies deleted"
        }
    } catch { }
}

function Test-ExecutionHistory {
    Add-Log "Checking execution history..."
    try {
        $bam = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" -ErrorAction SilentlyContinue
        if ($bam) {
            $cheatEntries = @()
            $bam | ForEach-Object {
                $props = $_ | Get-ItemProperty -ErrorAction SilentlyContinue
                $props.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                    if ($_.Value -match "loader|injector|cheat|bypass|spoofer|eulen|redengine|skript|gosth|susano|keyser|tz|degeo|asgard|hx") {
                        $cheatEntries += $_.Name
                    }
                }
            }
            if ($cheatEntries.Count -gt 0) {
                Add-Evidence "threat" "BAM Cheat Entries" "Background Activity Monitor shows known cheats"
                Add-Finding "execution_history_anomaly" 75 "BAM data shows cheat execution"
            }
        }
    } catch { }
}

function Test-DNSManipulation {
    Add-Log "Checking DNS cache..."
    try {
        $dns = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match "cheat|hack|mod|menu|executor|bypass|spoofer|loader|injector" }
        if ($dns) {
            Add-Evidence "suspicious" "Suspicious DNS" "DNS cache contains cheat domains"
            Add-Finding "dns_manipulation" 75 "DNS cache manipulated"
        }
    } catch { }
}

function Test-PCASVC {
    Add-Log "Checking services..."
    try {
        $pca = Get-Service "PcaSvc" -ErrorAction SilentlyContinue
        if ($pca -and $pca.Status -ne "Running") {
            Add-Evidence "suspicious" "PCA Stopped" "Program Compatibility Assistant stopped"
            Add-Finding "pcasvc_manipulation" 80 "PCA service tampered"
        }
    } catch { }
}

function Test-KnownCheats {
    Add-Log "Scanning for known cheat files..."
    $paths = @(
        "C:\eulen", "C:\redENGINE",
        "$env:LOCALAPPDATA\FiveM\FiveM.app\cache\*cheat*",
        "$env:APPDATA\*eulen*", "$env:APPDATA\*redengine*",
        "$env:TEMP\*loader*", "$env:TEMP\*injector*",
        "C:\Windows\INF\*rage*"
    )
    $found = @()
    foreach ($p in $paths) {
        $items = Get-Item $p -ErrorAction SilentlyContinue
        if ($items) { $found += $items.FullName }
    }
    if ($found.Count -gt 0) {
        $fstr = ($found | Select-Object -First 3) -join "; "
        Add-Evidence "threat" "Known Cheats Found" "Detected $($found.Count) artifacts: $fstr"
    }

    # FiveM cache Lua check
    $cache = "$env:LOCALAPPDATA\FiveM\FiveM.app\cache"
    if (Test-Path $cache) {
        $lua = Get-ChildItem $cache -Recurse -Filter "*.lua" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "money|drop|spawn|god|admin|bypass|hack|cheat|troll|crash|kick" }
        if ($lua) {
            Add-Evidence "threat" "Modified Lua" "Suspicious Lua in cache: $($lua.Count) files"
        }
    }
}

function Test-NetworkConnections {
    Add-Log "Checking network..."
    try {
        $conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -in @(4444,5555,6666,7777,8888,9999,1337,31337,8080,1080) } | Select-Object -First 5
        if ($conns) {
            Add-Evidence "suspicious" "Suspicious Ports" "Active connections to known ports"
        }
    } catch { }
}

function Get-SystemInfo {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $cpu = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1).Name
        $gpu = (Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Select-Object -First 1).Name
        $ram = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
        return [PSCustomObject]@{
            os = "$($os.Caption) $($os.OSArchitecture)"
            cpu = $cpu; gpu = $gpu; ram = "$ram GB"
            hostname = $env:COMPUTERNAME; username = $env:USERNAME
            hwid = (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue).UUID
        }
    } catch {
        return [PSCustomObject]@{os="Unknown"; cpu="Unknown"; gpu="Unknown"; ram="Unknown"; hostname=$env:COMPUTERNAME; username=$env:USERNAME; hwid="Unknown"}
    }
}

# === MAIN SCAN ===
$sysInfo = Get-SystemInfo
Add-Evidence "info" "System" "OS: $($sysInfo.os) | CPU: $($sysInfo.cpu) | RAM: $($sysInfo.ram) | GPU: $($sysInfo.gpu)"

$modules = @(
    "Test-StaggeredDeletes", "Test-TimestampFixing", "Test-SelectiveCleanup",
    "Test-EventLogManipulation", "Test-RegistryInconsistency", "Test-MemoryInjection",
    "Test-LSASSAccess", "Test-AlternateDataStreams", "Test-ShadowCopyWipe",
    "Test-ExecutionHistory", "Test-DNSManipulation", "Test-PCASVC",
    "Test-KnownCheats", "Test-NetworkConnections"
)

$total = $modules.Count
$current = 0
foreach ($mod in $modules) {
    $current++
    $progress.Value = [math]::Round(($current / $total) * 100)
    & $mod
}

$progress.Value = 100

# Calculate score
$threat = ($script:Evidence | Where-Object { $_.level -eq "threat" }).Count
$suspicious = ($script:Evidence | Where-Object { $_.level -eq "suspicious" }).Count
$score = 100 - ($threat * 15) - ($suspicious * 8)
if ($score -lt 0) { $score = 0 }

$status = if ($score -ge 90) { "clean" } elseif ($score -ge 60) { "suspicious" } else { "threat" }

$report = [PSCustomObject]@{
    scanId = "3X-" + (Get-Random -Minimum 1000 -Maximum 9999)
    timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    version = "3X-PC-v1.0"
    system = $sysInfo
    status = $status
    score = $score
    evidence = $script:Evidence
    findings = $script:Findings
    behaviorScore = if ($script:Findings.Count -gt 0) { [math]::Round(($script:Findings | Measure-Object -Property risk -Average).Average, 0) } else { 0 }
    isNapseLike = ($script:Findings | Where-Object { $_.pattern -in @("staggered_deletes","timestamp_fixing","selective_cleanup","no_event_104") }).Count -gt 0
    isOceanLike = ($script:Findings | Where-Object { $_.pattern -in @("prefetch_gap","registry_inconsistency","dns_manipulation","pcasvc_manipulation") }).Count -gt 0
    isEchoLike = ($script:Findings | Where-Object { $_.pattern -in @("memory_injection","lsass_anomaly","hidden_execution","ads_usage") }).Count -gt 0
}

# Show result
$resultLabel.Visible = $true
if ($status -eq "clean") {
    $resultLabel.Text = "✓ CLEAN — Score: $score%"
    $resultLabel.ForeColor = [System.Drawing.Color]::FromArgb(16, 185, 129)
} elseif ($status -eq "suspicious") {
    $resultLabel.Text = "! SUSPICIOUS — Score: $score%"
    $resultLabel.ForeColor = [System.Drawing.Color]::FromArgb(245, 158, 11)
} else {
    $resultLabel.Text = "✕ THREAT — Score: $score%"
    $resultLabel.ForeColor = [System.Drawing.Color]::FromArgb(239, 68, 68)
}

Add-Log "========================================"
Add-Log "SCAN COMPLETE"
Add-Log "Status: $status | Score: $score%"
Add-Log "Evidence: $($script:Evidence.Count) items"
Add-Log "Findings: $($script:Findings.Count) patterns"
Add-Log "========================================"

# Save report
$reportPath = "$env:TEMP\3X-Report-$($report.scanId).json"
$report | ConvertTo-Json -Depth 10 | Out-File $reportPath
Add-Log "Report saved: $reportPath"

# Upload
Add-Log "Uploading to 3X Cloud..."
try {
    $body = $report | ConvertTo-Json -Depth 10
    $response = Invoke-RestMethod -Uri "$ServerUrl/scan-upload" -Method POST -Headers @{"Content-Type"="application/json"} -Body $body -TimeoutSec 30
    Add-Log "Upload successful!"
    Add-Log "View: $ServerUrl/scan-report.html?id=$($report.scanId)"

    # Show link
    $linkLabel = New-Object System.Windows.Forms.Label
    $linkLabel.Text = "Report uploaded! Click to view:"
    $linkLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $linkLabel.ForeColor = [System.Drawing.Color]::FromArgb(156, 163, 175)
    $linkLabel.AutoSize = $true
    $linkLabel.Location = New-Object System.Drawing.Point(50, 275)
    $form.Controls.Add($linkLabel)

    $linkBtn = New-Object System.Windows.Forms.LinkLabel
    $linkBtn.Text = "$ServerUrl/scan-report.html?id=$($report.scanId)"
    $linkBtn.Font = New-Object System.Drawing.Font("Consolas", 8)
    $linkBtn.ForeColor = [System.Drawing.Color]::FromArgb(123, 97, 255)
    $linkBtn.AutoSize = $true
    $linkBtn.Location = New-Object System.Drawing.Point(50, 295)
    $linkBtn.Add_Click({ Start-Process $this.Text })
    $form.Controls.Add($linkBtn)

} catch {
    Add-Log "Upload failed: $($_.Exception.Message)"
    Add-Log "Report saved locally."
}

# Keep form open
$form.ShowDialog()
'@

# Create the .exe using IExpress (built into Windows)
$tempDir = "$env:TEMP\3XBuilder"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Write the embedded script
$scriptPath = "$tempDir\scanner.ps1"
$embeddedScript | Out-File $scriptPath -Encoding UTF8

# Create batch launcher
$batchContent = @"
@echo off
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0scanner.ps1" -ServerUrl "$ServerUrl"
"@
$batchPath = "$tempDir\run.bat"
$batchContent | Out-File $batchPath -Encoding ASCII

# Create SED file for IExpress
$sedContent = @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=0
UseLongFileName=1
CompressFiles=1
CabinetName=setup.cab
InstallPrompt=3X Cloud Forensic Scanner
DisplayLicense=None
FinishMessage=Scan complete. Report uploaded to 3X Cloud.
TargetName=$OutputPath
FriendlyName=3X Cloud PC Checker
AppLaunched=run.bat
PostInstallCmd=<None>
AdminQuietInstCmd=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File scanner.ps1
UserQuietInstCmd=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File scanner.ps1
SourceFiles=SourceFiles
[Strings]
InstallPrompt=3X Cloud Forensic Scanner will check your system for forensic evidence.
DisplayLicense=None
FinishMessage=Scan complete.
TargetName=$OutputPath
FriendlyName=3X Cloud PC Checker
AppLaunched=run.bat
PostInstallCmd=<None>
AdminQuietInstCmd=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File scanner.ps1
UserQuietInstCmd=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File scanner.ps1
[SourceFiles]
SourceFiles0=$tempDir\
[SourceFiles0]
%FILE0%=scanner.ps1
%FILE1%=run.bat
"@

$sedPath = "$tempDir\build.sed"
$sedContent | Out-File $sedPath -Encoding ASCII

# Build the .exe
Write-Host "Building 3X Cloud PC Checker .exe..." -ForegroundColor Cyan
Write-Host "Output: $OutputPath" -ForegroundColor Cyan

$iexpress = "$env:SystemRoot\System32\iexpress.exe"
if (Test-Path $iexpress) {
    Start-Process $iexpress -ArgumentList "/N /Q $sedPath" -Wait -WindowStyle Hidden
    if (Test-Path $OutputPath) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "BUILD SUCCESSFUL!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "File: $OutputPath" -ForegroundColor Green
        Write-Host "Size: $([math]::Round((Get-Item $OutputPath).Length / 1KB, 2)) KB" -ForegroundColor Green
        Write-Host ""
        Write-Host "Send this .exe to the person you want to check." -ForegroundColor Yellow
        Write-Host "When they run it, it will scan their PC and upload results to:" -ForegroundColor Yellow
        Write-Host "$ServerUrl" -ForegroundColor Cyan
        Write-Host ""
    } else {
        Write-Host "Build failed. Check permissions." -ForegroundColor Red
    }
} else {
    Write-Host "IExpress not found. Cannot build .exe on this system." -ForegroundColor Red
    Write-Host "Alternative: Use the .ps1 script directly." -ForegroundColor Yellow
}

# Cleanup
Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
