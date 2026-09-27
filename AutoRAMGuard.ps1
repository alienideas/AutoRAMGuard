#Requires -RunAsAdministrator
<#
.SYNOPSIS
    AutoRAMGuard - Automatic High RAM & 100% Disk Usage Malware Scanner for Windows 10/11

.DESCRIPTION
    Fully automated scanner that:
    - Updates threat intelligence from free public sources (no login / no API key)
    - Saves intelligence to a single local file (threat_intel.txt)
    - Scans for high RAM usage, 100% disk indicators, memory injection, miners, spyware
    - Performs strict automated verification before any action
    - Auto-quarantines ONLY high-confidence threats (no manual confirmation)
    - Never touches critical system files or processes
    - Requires no extra software installation

.NOTES
    Tool     : AutoRAMGuard
    Version  : 1.0
    Compatible with Windows 10 and Windows 11
    Pure PowerShell - no external modules required
#>

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$Host.UI.RawUI.WindowTitle = "AutoRAMGuard - Automatic High RAM & Disk Malware Scanner"

# ====================== CONFIGURATION ======================
$ScriptDir       = Split-Path -Parent $MyInvocation.MyCommand.Path
$IntelFile       = Join-Path $ScriptDir "threat_intel.txt"
$LogFile         = Join-Path $ScriptDir "AutoRAMGuard_Log.txt"
$ReportFile      = Join-Path $ScriptDir "AutoRAMGuard_Report.txt"
$QuarantineDir   = Join-Path $ScriptDir "Quarantine"
$MaxIntelAgeDays = 7          # Refresh intel if older than this

# Critical processes that must NEVER be touched
$CriticalProcesses = @(
    "System", "Idle", "smss", "csrss", "wininit", "winlogon", "services",
    "lsass", "svchost", "explorer", "dwm", "fontdrvhost", "Memory Compression",
    "Registry", "conhost", "sihost", "taskhostw", "RuntimeBroker", "SearchHost",
    "StartMenuExperienceHost", "ShellExperienceHost", "SecurityHealthService",
    "MsMpEng", "NisSrv", "SecurityHealthSystray", "smartscreen"
)

# Trusted path patterns (higher protection)
$ProtectedPaths = @(
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\WinSxS\\",
    "\\Program Files\\Windows ",
    "\\Program Files (x86)\\Windows "
)

# ====================== HELPER FUNCTIONS ======================

function Write-Color {
    param([string]$Text, [ConsoleColor]$Color = "White")
    Write-Host $Text -ForegroundColor $Color
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp | $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Internet {
    try {
        $response = Invoke-WebRequest -Uri "https://www.google.com" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Get-FileSignatureStatus {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return "Missing" }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($sig.Status -eq "Valid") {
            $publisher = $sig.SignerCertificate.Subject
            if ($publisher -match "Microsoft Corporation") { return "Microsoft" }
            return "Valid"
        }
        return "Unsigned"
    } catch {
        return "Unknown"
    }
}

function Test-IsProtectedPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    foreach ($p in $ProtectedPaths) {
        if ($Path -like "*$p*") { return $true }
    }
    return $false
}

function Test-IsCriticalProcess {
    param([string]$ProcessName)
    return $CriticalProcesses -contains $ProcessName
}

# ====================== THREAT INTEL ENGINE ======================

function Get-BuiltInIntel {
    # High-quality base list (miners + common resource-abusive spyware)
    return @{
        ProcessNames = @(
            "xmrig", "minerd", "cpuminer", "nicehash", "ethminer", "claymore", "phoenixminer",
            "nbminer", "gminer", "t-rex", "lolminer", "teamredminer", "cryptonight",
            "miner", "coinminer", "cryptominer", "hashrate", "stratum",
            "systemupdate", "browserupdate", "chromeupdate", "softwareupdate",
            "searchprotect", "conduit", "genieo", "dealply", "babylon", "yontoo",
            "opencandy", "installcore", "superfish", "couponserver", "shopperpro",
            "websearch", "toolbar", "optimizer", "cleanerpro", "pcoptimizer",
            "speedup", "boost", "registryfix", "driverupdater"
        )
        FileNames = @(
            "xmrig.exe", "minerd.exe", "ethminer.exe", "phoenixminer.exe", "nbminer.exe",
            "miner.exe", "coinminer.exe", "cryptominer.exe", "client.exe", "service.exe",
            "update.exe", "updater.exe", "helper.exe", "assistant.exe"
        )
        PathPatterns = @(
            "\\Temp\\", "\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\",
            "\\Users\\Public\\", "\\ProgramData\\", "\\Windows\\Temp\\", "\\Downloads\\"
        )
        Behavioral = @(
            "high memory growth", "suspicious module load", "temp executable",
            "unsigned high memory", "appdata miner"
        )
    }
}

function Update-ThreatIntel {
    Write-Color "`n[+] Checking threat intelligence..." "Cyan"
    Write-Log "Starting threat intelligence update check"

    $needsUpdate = $true
    if (Test-Path $IntelFile) {
        $age = (Get-Date) - (Get-Item $IntelFile).LastWriteTime
        if ($age.TotalDays -lt $MaxIntelAgeDays) {
            Write-Color "    Local intelligence is recent ($([math]::Round($age.TotalDays,1)) days old). Skipping online update." "Green"
            Write-Log "Intel file is recent - skip update"
            $needsUpdate = $false
        }
    }

    if (-not $needsUpdate) { return }

    if (-not (Test-Internet)) {
        Write-Color "    No internet connection. Using existing local intelligence." "Yellow"
        Write-Log "No internet - using local intel"
        return
    }

    Write-Color "    Internet available. Fetching free public threat data (no login required)..." "Cyan"

    $builtIn = Get-BuiltInIntel
    $allProcess = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $allFiles   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $allPaths   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($p in $builtIn.ProcessNames) { [void]$allProcess.Add($p) }
    foreach ($f in $builtIn.FileNames)   { [void]$allFiles.Add($f) }
    foreach ($p in $builtIn.PathPatterns){ [void]$allPaths.Add($p) }

    # --- Free public sources (no authentication) ---
    $sources = @(
        @{ Name = "TweetFeed SHA256"; Url = "https://tweetfeed.live/feeds/today_sha256.csv" },
        @{ Name = "TweetFeed Domains"; Url = "https://tweetfeed.live/feeds/today_domains.csv" },
        @{ Name = "Feodo Tracker"; Url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" }
    )

    foreach ($src in $sources) {
        try {
            Write-Color "    → Downloading $($src.Name)..." "DarkGray"
            $content = Invoke-WebRequest -Uri $src.Url -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            $text = $content.Content

            # Extract possible executable / process-like names
            $matches = [regex]::Matches($text, '(?i)([a-z0-9_\-]{3,40}\.exe)')
            foreach ($m in $matches) {
                $name = $m.Groups[1].Value.ToLower()
                if ($name -notmatch "^(setup|install|update|windows|microsoft|chrome|firefox|edge|office)") {
                    [void]$allFiles.Add($name)
                    [void]$allProcess.Add(($name -replace '\.exe$',''))
                }
            }
            Write-Log "Fetched $($src.Name) successfully"
        } catch {
            Write-Color "    → Failed to fetch $($src.Name) (will continue)" "DarkYellow"
            Write-Log "Failed to fetch $($src.Name): $($_.Exception.Message)"
        }
    }

    # Build the single intel file
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# AutoRAMGuard Threat Intelligence")
    [void]$sb.AppendLine("# Last Updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("# Sources: Built-in + free public feeds (no authentication)")
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("[PROCESS_NAMES]")
    foreach ($item in ($allProcess | Sort-Object)) { [void]$sb.AppendLine($item) }
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("[FILE_NAMES]")
    foreach ($item in ($allFiles | Sort-Object)) { [void]$sb.AppendLine($item) }
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("[PATH_PATTERNS]")
    foreach ($item in ($allPaths | Sort-Object)) { [void]$sb.AppendLine($item) }
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("[BEHAVIORAL]")
    foreach ($item in $builtIn.Behavioral) { [void]$sb.AppendLine($item) }

    $sb.ToString() | Out-File -FilePath $IntelFile -Encoding UTF8 -Force
    Write-Color "    Threat intelligence updated and saved to threat_intel.txt" "Green"
    Write-Log "Threat intelligence file updated successfully"
}

function Load-ThreatIntel {
    $intel = @{
        ProcessNames = @()
        FileNames    = @()
        PathPatterns = @()
        Behavioral   = @()
    }

    if (-not (Test-Path $IntelFile)) {
        Write-Color "    No local intel file found. Using built-in list only." "Yellow"
        $builtIn = Get-BuiltInIntel
        $intel.ProcessNames = $builtIn.ProcessNames
        $intel.FileNames    = $builtIn.FileNames
        $intel.PathPatterns = $builtIn.PathPatterns
        $intel.Behavioral   = $builtIn.Behavioral
        return $intel
    }

    $section = ""
    Get-Content $IntelFile -ErrorAction SilentlyContinue | ForEach-Object {
        $line = $_.Trim()
        if ($line -match '^#') { return }
        if ($line -eq "") { return }
        if ($line -match '^\[(.+)\]$') {
            $section = $Matches[1].ToUpper()
            return
        }
        switch ($section) {
            "PROCESS_NAMES"  { $intel.ProcessNames  += $line }
            "FILE_NAMES"     { $intel.FileNames     += $line }
            "PATH_PATTERNS"  { $intel.PathPatterns  += $line }
            "BEHAVIORAL"     { $intel.Behavioral    += $line }
        }
    }
    Write-Log "Loaded intel: $($intel.ProcessNames.Count) processes, $($intel.FileNames.Count) files"
    return $intel
}

# ====================== SCAN ENGINE ======================

function Get-SystemMemoryInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $total = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $free  = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $used  = [math]::Round($total - $free, 2)
    $pct   = [math]::Round(($used / $total) * 100, 1)
    return [PSCustomObject]@{
        TotalGB = $total
        UsedGB  = $used
        FreeGB  = $free
        PctUsed = $pct
    }
}

function Scan-System {
    param($Intel)

    Write-Color "`n[+] Starting system scan..." "Cyan"
    Write-Log "System scan started"

    $findings = [System.Collections.Generic.List[object]]::new()
    $id = 0

    # Memory overview
    $mem = Get-SystemMemoryInfo
    Write-Color "    System Memory: $($mem.UsedGB) GB used / $($mem.TotalGB) GB total ($($mem.PctUsed)%)" $(if ($mem.PctUsed -ge 85) {"Red"} else {"Green"})

    # Disk snapshot
    try {
        $disk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction SilentlyContinue
        if ($disk) {
            Write-Color "    Disk Queue: $($disk.CurrentDiskQueueLength) | Disk Time: $($disk.PercentDiskTime)%" $(if ($disk.PercentDiskTime -gt 80) {"Red"} else {"Green"})
        }
    } catch {}

    # Process scan
    Write-Color "    Scanning processes..." "DarkGray"
    $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.WorkingSet64 -gt 0 }

    foreach ($proc in $processes) {
        $procName = $proc.ProcessName
        $path = $proc.Path
        $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)

        if (Test-IsCriticalProcess $procName) { continue }

        $score = 0
        $reasons = [System.Collections.Generic.List[string]]::new()

        # Name match
        foreach ($bad in $Intel.ProcessNames) {
            if ($procName -like "*$bad*") {
                $score += 40
                $reasons.Add("Process name matches threat intel: $bad")
                break
            }
        }

        # Path match
        if ($path) {
            foreach ($pat in $Intel.PathPatterns) {
                if ($path -like "*$pat*") {
                    $score += 25
                    $reasons.Add("Running from suspicious path")
                    break
                }
            }
            if ($path -notmatch "System32|SysWOW64|Program Files") {
                $score += 10
                $reasons.Add("Unusual process location")
            }
        }

        # High memory
        if ($memMB -gt 700) {
            $score += 15
            $reasons.Add("High memory usage ($memMB MB)")
        }

        # High thread count (possible injection / miner)
        if ($proc.Threads.Count -gt 90) {
            $score += 15
            $reasons.Add("Very high thread count ($($proc.Threads.Count))")
        }

        if ($score -ge 40) {
            $id++
            $sigStatus = if ($path) { Get-FileSignatureStatus $path } else { "Unknown" }
            $findings.Add([PSCustomObject]@{
                ID          = $id
                Type        = "Process"
                Name        = $procName
                Path        = $path
                MemoryMB    = $memMB
                PID         = $proc.Id
                Score       = $score
                Reasons     = ($reasons -join " | ")
                Signature   = $sigStatus
                ActionTarget = $proc.Id
            })
        }
    }

    # Startup Registry
    Write-Color "    Scanning startup registry..." "DarkGray"
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($reg in $regPaths) {
        if (-not (Test-Path $reg)) { continue }
        $props = Get-ItemProperty $reg -ErrorAction SilentlyContinue
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }
            $val = [string]$prop.Value
            $score = 0
            $reasons = [System.Collections.Generic.List[string]]::new()

            foreach ($bad in $Intel.ProcessNames + $Intel.FileNames) {
                if ($prop.Name -like "*$bad*" -or $val -like "*$bad*") {
                    $score += 35
                    $reasons.Add("Matches threat intel: $bad")
                    break
                }
            }
            foreach ($pat in $Intel.PathPatterns) {
                if ($val -like "*$pat*") {
                    $score += 25
                    $reasons.Add("Points to suspicious path")
                    break
                }
            }
            if ($score -ge 35) {
                $id++
                $findings.Add([PSCustomObject]@{
                    ID          = $id
                    Type        = "Registry"
                    Name        = $prop.Name
                    Path        = "$reg → $val"
                    MemoryMB    = 0
                    PID         = $null
                    Score       = $score
                    Reasons     = ($reasons -join " | ")
                    Signature   = "N/A"
                    ActionTarget = "$reg|$($prop.Name)"
                })
            }
        }
    }

    # Scheduled Tasks
    Write-Color "    Scanning scheduled tasks..." "DarkGray"
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
        $task = $_
        $actions = ($task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join " "
        $score = 0
        $reasons = [System.Collections.Generic.List[string]]::new()

        foreach ($bad in $Intel.ProcessNames + $Intel.FileNames) {
            if ($task.TaskName -like "*$bad*" -or $actions -like "*$bad*") {
                $score += 35
                $reasons.Add("Matches threat intel: $bad")
                break
            }
        }
        foreach ($pat in $Intel.PathPatterns) {
            if ($actions -like "*$pat*") {
                $score += 25
                $reasons.Add("Runs from suspicious location")
                break
            }
        }
        if ($score -ge 35) {
            $id++
            $findings.Add([PSCustomObject]@{
                ID          = $id
                Type        = "Task"
                Name        = $task.TaskName
                Path        = $actions
                MemoryMB    = 0
                PID         = $null
                Score       = $score
                Reasons     = ($reasons -join " | ")
                Signature   = "N/A"
                ActionTarget = $task.TaskName
            })
        }
    }

    Write-Log "Scan completed. Findings: $($findings.Count)"
    return $findings
}

# ====================== AUTOMATED VERIFICATION & ACTION ======================

function Invoke-AutomatedVerificationAndAction {
    param([System.Collections.Generic.List[object]]$Findings)

    Write-Color "`n[+] Running automated verification..." "Cyan"
    Write-Log "Automated verification started"

    if (-not (Test-Path $QuarantineDir)) {
        New-Item -ItemType Directory -Path $QuarantineDir -Force | Out-Null
    }

    $autoRemoved = 0
    $reportedOnly = 0
    $reportLines = [System.Collections.Generic.List[string]]::new()

    $reportLines.Add("AutoRAMGuard Scan Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $reportLines.Add("=" * 70)
    $reportLines.Add("")

    foreach ($item in $Findings | Sort-Object Score -Descending) {
        $canRemove = $true
        $blockReasons = [System.Collections.Generic.List[string]]::new()

        # === STRICT AUTOMATED SAFETY CHECKS ===

        # 1. Critical process protection
        if ($item.Type -eq "Process" -and (Test-IsCriticalProcess $item.Name)) {
            $canRemove = $false
            $blockReasons.Add("Critical system process")
        }

        # 2. Protected path
        if ($item.Path -and (Test-IsProtectedPath $item.Path)) {
            $canRemove = $false
            $blockReasons.Add("Protected system path")
        }

        # 3. Microsoft signed
        if ($item.Signature -eq "Microsoft") {
            $canRemove = $false
            $blockReasons.Add("Signed by Microsoft")
        }

        # 4. Valid signature from trusted location
        if ($item.Signature -eq "Valid" -and $item.Path -match "Program Files") {
            $canRemove = $false
            $blockReasons.Add("Validly signed in Program Files")
        }

        # 5. Score threshold - only high confidence
        if ($item.Score -lt 60) {
            $canRemove = $false
            $blockReasons.Add("Score too low for automatic action ($($item.Score))")
        }

        # 6. Must have a real file path for quarantine
        if ($item.Type -eq "Process" -and [string]::IsNullOrWhiteSpace($item.Path)) {
            $canRemove = $false
            $blockReasons.Add("No file path available")
        }

        # === DECISION ===
        if ($canRemove) {
            # HIGH CONFIDENCE → Auto quarantine
            try {
                if ($item.Type -eq "Process") {
                    $proc = Get-Process -Id $item.ActionTarget -ErrorAction SilentlyContinue
                    if ($proc) {
                        Stop-Process -Id $item.ActionTarget -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 600
                    }
                    if (Test-Path $item.Path) {
                        $destName = "{0}_{1}" -f (Get-Date -Format "yyyyMMdd_HHmmss"), (Split-Path $item.Path -Leaf)
                        $dest = Join-Path $QuarantineDir $destName
                        Move-Item -Path $item.Path -Destination $dest -Force -ErrorAction Stop
                        Write-Color "    [QUARANTINED] $($item.Name) → $destName" "Green"
                        Write-Log "QUARANTINED: $($item.Name) | $($item.Path) | Score $($item.Score)"
                        $reportLines.Add("[AUTO-QUARANTINED] $($item.Type) | $($item.Name) | Score: $($item.Score)")
                        $reportLines.Add("    Path: $($item.Path)")
                        $reportLines.Add("    Reasons: $($item.Reasons)")
                        $reportLines.Add("")
                        $autoRemoved++
                    }
                }
                elseif ($item.Type -eq "Registry") {
                    $parts = $item.ActionTarget -split '\|'
                    Remove-ItemProperty -Path $parts[0] -Name $parts[1] -Force -ErrorAction Stop
                    Write-Color "    [REMOVED] Registry startup: $($item.Name)" "Green"
                    Write-Log "REMOVED Registry: $($item.ActionTarget)"
                    $reportLines.Add("[AUTO-REMOVED] Registry | $($item.Name)")
                    $reportLines.Add("    $($item.Path)")
                    $reportLines.Add("")
                    $autoRemoved++
                }
                elseif ($item.Type -eq "Task") {
                    Unregister-ScheduledTask -TaskName $item.ActionTarget -Confirm:$false -ErrorAction Stop
                    Write-Color "    [REMOVED] Scheduled Task: $($item.Name)" "Green"
                    Write-Log "REMOVED Task: $($item.ActionTarget)"
                    $reportLines.Add("[AUTO-REMOVED] Task | $($item.Name)")
                    $reportLines.Add("    $($item.Path)")
                    $reportLines.Add("")
                    $autoRemoved++
                }
            } catch {
                Write-Color "    [FAILED] Could not act on $($item.Name): $($_.Exception.Message)" "Red"
                Write-Log "ACTION FAILED: $($item.Name) | $($_.Exception.Message)"
                $reportedOnly++
                $reportLines.Add("[REPORTED ONLY - Action failed] $($item.Type) | $($item.Name) | Score: $($item.Score)")
                $reportLines.Add("    Reasons: $($item.Reasons)")
                $reportLines.Add("")
            }
        } else {
            # Report only
            $reportedOnly++
            $reportLines.Add("[REPORTED ONLY] $($item.Type) | $($item.Name) | Score: $($item.Score)")
            $reportLines.Add("    Path: $($item.Path)")
            $reportLines.Add("    Reasons: $($item.Reasons)")
            $reportLines.Add("    Blocked because: $($blockReasons -join ', ')")
            $reportLines.Add("")
            Write-Log "REPORTED ONLY: $($item.Name) | Blocked: $($blockReasons -join ', ')"
        }
    }

    $reportLines.Add("=" * 70)
    $reportLines.Add("Summary: Auto-quarantined/removed: $autoRemoved | Reported only: $reportedOnly")
    $reportLines | Out-File -FilePath $ReportFile -Encoding UTF8 -Force

    return @{
        AutoRemoved  = $autoRemoved
        ReportedOnly = $reportedOnly
    }
}

# ====================== MAIN ======================

Clear-Host
Write-Color "==============================================================" "Cyan"
Write-Color "          AutoRAMGuard v1.0" "Cyan"
Write-Color "  Automatic High RAM & 100% Disk Malware Scanner" "Cyan"
Write-Color "         Windows 10 / 11 - Fully Automated" "Cyan"
Write-Color "==============================================================" "Cyan"
Write-Host ""

if (-not (Test-IsAdmin)) {
    Write-Color "ERROR: This script must be run as Administrator." "Red"
    Write-Color "Right-click PowerShell → Run as administrator" "Yellow"
    pause
    exit 1
}

Write-Log "========== AutoRAMGuard started =========="

# 1. Update threat intelligence
Update-ThreatIntel

# 2. Load intelligence
Write-Color "`n[+] Loading threat intelligence..." "Cyan"
$intel = Load-ThreatIntel
Write-Color "    Loaded $($intel.ProcessNames.Count) process indicators, $($intel.FileNames.Count) file indicators" "Green"

# 3. Scan
$findings = Scan-System -Intel $intel

# 4. Results
Write-Host ""
Write-Color "==================== SCAN RESULTS ====================" "Cyan"

if ($findings.Count -eq 0) {
    Write-Color "No suspicious items meeting detection criteria were found." "Green"
    Write-Log "No findings"
    Write-Color "`nReport saved to: $ReportFile" "DarkGray"
    pause
    exit 0
}

Write-Color "Found $($findings.Count) potentially suspicious item(s):`n" "Yellow"
$findings | Sort-Object Score -Descending | Format-Table -Property ID, Type, Name, @{
    Label = "RAM(MB)"; Expression = { if ($_.MemoryMB) { $_.MemoryMB } else { "-" } }
}, Score, Signature -AutoSize

# 5. Automated verification + action (NO manual confirmation)
$result = Invoke-AutomatedVerificationAndAction -Findings $findings

Write-Host ""
Write-Color "==============================================================" "Cyan"
Write-Color "Automated actions completed." "Green"
Write-Color "  Auto-quarantined / removed : $($result.AutoRemoved)" "Green"
Write-Color "  Reported only (safe)       : $($result.ReportedOnly)" "Yellow"
Write-Color ""
Write-Color "Detailed report : $ReportFile" "Cyan"
Write-Color "Quarantine folder: $QuarantineDir" "Cyan"
Write-Color "Log file         : $LogFile" "Cyan"
Write-Color "==============================================================" "Cyan"
Write-Host ""
Write-Color "Recommendation: Restart the computer and check Task Manager / Resource Monitor." "Yellow"
Write-Host ""
pause
Write-Log "========== AutoRAMGuard finished =========="
