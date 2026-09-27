# AutoRAMGuard

### Automatic High RAM & 100% Disk Usage Malware Scanner for Windows 10/11

**Free • Fully Automated • No Installation • No Login Required**

AutoRAMGuard detects and safely removes spyware, crypto miners, and memory-hijacking malware that cause **high RAM usage (90%+)** and **100% disk usage** on Windows 10 and Windows 11.

Just run the script. Everything else is automatic.

[![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-blue?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell)](https://docs.microsoft.com/powershell)
[![No Login](https://img.shields.io/badge/No%20Login-Required-success?style=flat-square)](#)
[![Offline Capable](https://img.shields.io/badge/Works-Offline-orange?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](#license)

---

## Why AutoRAMGuard?

Millions of Windows users suffer from:

- Extremely high RAM usage after startup
- Constant 100% disk activity that freezes the PC
- Hidden crypto miners and spyware consuming resources
- Memory injection and process hijacking malware

Most tools require installation, accounts, or constant internet.  
**AutoRAMGuard works fully automatically with zero setup.**

---

## Key Features

| Feature | Benefit |
|---------|---------|
| **Fully Automatic** | User only runs the script – no questions asked |
| **High RAM Detection** | Finds processes causing 90%+ memory usage |
| **100% Disk Detection** | Identifies disk-hogging malware and miners |
| **Crypto Miner Detection** | Built-in + live indicators for popular miners |
| **Memory Hijack Indicators** | Detects suspicious injection patterns |
| **Free Public Threat Intel** | Updates from free sources (no login / no API key) |
| **Single Intel File** | All data stored locally in `threat_intel.txt` |
| **Strict Safety Engine** | Only high-confidence threats are auto-quarantined |
| **No Manual Confirmation** | Automated verification decides what is safe |
| **Quarantine System** | Suspicious files are moved, not permanently deleted |
| **Zero Installation** | Pure PowerShell – works on clean Windows |
| **Full Logging** | Every action is recorded |

---

## How It Works

1. Checks internet connection
2. Downloads free public threat intelligence (no account needed)
3. Saves data to local `threat_intel.txt`
4. Scans processes, memory, disk, startup entries, and scheduled tasks
5. Runs strict automated safety verification
6. Auto-quarantines only high-confidence threats
7. Generates detailed report and log

---

## Safety First Design

AutoRAMGuard will **never** automatically remove an item unless it passes **all** of these checks:

- Matches known threat indicators
- Located in a suspicious folder (Temp, AppData, Public, etc.)
- Not a critical Windows system process
- Not inside protected system directories (`System32`, `SysWOW64`)
- Not signed by Microsoft
- Reaches a high confidence score

Critical processes and system files are completely protected.

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or newer (already included)
- Administrator rights

**No additional software or modules required.**

---

## How to Use

1. Right-click **Windows PowerShell** or **Terminal** → **Run as administrator**
2. Go to the script folder:
   ```powershell
   cd "C:\Path\To\AutoRAMGuard"
   ```
3. Allow the script for this session:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   ```
4. Run:
   ```powershell
   .\AutoRAMGuard.ps1
   ```

Done. The tool handles everything automatically.

---

## Generated Files

| File | Purpose |
|------|---------|
| `threat_intel.txt` | Local threat intelligence (auto-updated) |
| `AutoRAMGuard_Report.txt` | Full scan report |
| `AutoRAMGuard_Log.txt` | Detailed activity log |
| `Quarantine\` | Folder containing quarantined threats |

---

## SEO Keywords

`high ram usage windows 10`, `100% disk usage fix`, `high memory usage malware`, `crypto miner detector windows`, `spyware remover automatic`, `memory hijack scanner`, `windows 11 slow startup malware`, `free offline malware scanner`, `automatic high ram cleaner`, `remove disk hogging malware`, `powershell malware scanner`, `no installation virus scanner`

---

## Disclaimer

AutoRAMGuard is a heuristic and intelligence-based tool. It is **not** a replacement for a full antivirus.  
Always keep Windows Defender or another real-time protection enabled.  
Use at your own risk.

---

## License

MIT License – free to use, modify, and distribute.

---

**Star this repository if AutoRAMGuard helped fix your high RAM or 100% disk problem.**
