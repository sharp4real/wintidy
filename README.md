# WinTidy

Windows performance optimization tool that removes bloatware and maximizes gaming performance.

![Version](https://img.shields.io/badge/version-1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-purple)

## Quick Install

Run this command in PowerShell (as Administrator):

```powershell
irm https://github.com/sharp4real/wintidy/releases/download/v1.0/WinTidy.ps1 | iex
```

Or download and run manually:

```powershell
Invoke-WebRequest -Uri "https://github.com/sharp4real/wintidy/releases/download/v1.0/WinTidy.ps1" -OutFile "$env:TEMP\WinTidy.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\WinTidy.ps1"
```

## Features

### Bloatware Removal
- Removes 30+ default Windows apps
- Uninstalls Edge, OneDrive, Cortana
- Removes Xbox apps, Skype, Teams
- Cleans up Windows Store bloat

### Gaming Optimizations
- Disables Game DVR (major FPS boost)
- Enables Game Mode
- Maximizes GPU priority (priority 8)
- Optimizes CPU scheduling for games
- Sets High Performance power plan

### Performance Tweaks
- Disables 15+ unnecessary background services
- Disables Windows Search indexing
- Disables memory compression
- Disables prefetch/superfetch
- Optimizes paging file settings

### Network Optimization
- Enables TCP/IP chimney offload
- Disables Nagle's algorithm
- Optimizes network stack for gaming
- Reduces network latency

### Privacy & Telemetry
- Disables all Windows telemetry
- Disables Cortana
- Disables activity tracking
- Disables advertising ID
- Removes telemetry scheduled tasks

### Security Note
- Disables Windows Defender real-time protection
- **Install third-party antivirus after running**

## Safety Features

- ✅ Automatic system restore point creation
- ✅ Registry backup before modifications
- ✅ Registry validation to prevent corruption
- ✅ Detailed logging to file
- ✅ Two-step confirmation process
- ✅ Revert functionality included

## Requirements

- Windows 10 or Windows 11
- Administrator privileges
- PowerShell 5.1 or higher
- Active internet connection (for one-liner install)

## Usage

### Method 1: One-Liner (Recommended)
1. Right-click Start Menu → Windows PowerShell (Admin)
2. Paste the install command
3. Press Enter
4. GUI will open automatically

### Method 2: Manual Download
1. Download `WinTidy.ps1` from [Releases](https://github.com/sharp4real/wintidy/releases)
2. Right-click the file → Run with PowerShell
3. Or open PowerShell as Admin and run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "C:\path\to\WinTidy.ps1"
   ```

### Using the GUI
1. Close all applications before starting
2. Click **"APPLY TWEAKS"**
3. Read and accept the disclaimer
4. Confirm you accept responsibility
5. Wait for optimization to complete (5-10 minutes)
6. Restart your computer

### Reverting Changes
1. Open WinTidy
2. Click **"REVERT TWEAKS"**
3. Restart your computer

**Note:** Removed applications cannot be automatically reinstalled. You must reinstall them manually from Microsoft Store.

## Expected Performance Gains

- Lower background CPU usage
- Reduced RAM consumption
- Improved frame consistency in games
- Lower system latency
- Faster boot times
- Reduced disk activity

## What Gets Modified

### Removed Applications
- Microsoft Edge
- OneDrive
- Cortana
- Xbox (Game Bar, Game Overlay, etc.)
- Skype
- Teams
- Your Phone
- 3D Viewer, Paint 3D
- Weather, News, Maps
- Solitaire Collection
- And 20+ more

### Disabled Services
- DiagTrack (telemetry)
- Windows Search
- Xbox services
- Remote Registry
- Retail Demo
- And 10+ more

### Registry Modifications
- Game DVR disabled
- Game Mode enabled
- GPU priority maximized
- Network stack optimized
- Telemetry disabled
- Activity tracking disabled

## Logs and Backups

All backups and logs are stored in:
```
%TEMP%\WinTidy_Backup_[timestamp]\
```

Contains:
- Registry backups (.xml files)
- Full optimization log (optimization.log)

## Troubleshooting

### Script won't run
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

### Need to restore system
Use Windows System Restore:
1. Search "Create a restore point"
2. Click "System Restore"
3. Select "WinTidy_Before_Optimization"

### Want to reinstall removed apps
Open Microsoft Store and search for the app, or use:
```powershell
Get-AppxPackage -AllUsers | Where-Object {$_.Name -like "*AppName*"} | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
```

## Important Warnings

⚠️ **READ BEFORE RUNNING:**
- Backup your important data first
- Close all running applications
- This makes permanent changes to Windows
- Some features will be disabled permanently
- Windows Update may reinstall some components
- You must install third-party antivirus
- **You assume full responsibility for any issues**

## Compatibility

✅ Windows 10 (all versions)  
✅ Windows 11 (all versions)  
❌ Windows Server (not tested)  
❌ Windows 8.1 or older (not supported)

## FAQ

**Q: Will this break Windows?**  
A: No, but it disables many features. A restore point is created automatically.

**Q: Can I undo the changes?**  
A: Most changes can be reverted with the "REVERT TWEAKS" button. Removed apps must be reinstalled manually.

**Q: Is this safe?**  
A: Yes, but you assume all responsibility. Always backup first.

**Q: Will Windows Update undo these changes?**  
A: Some changes may be reverted by major Windows updates. Some apps may reinstall.

**Q: Why disable Windows Defender?**  
A: Performance gain. Install alternative antivirus like Malwarebytes, Bitdefender, or Kaspersky.

**Q: How much FPS gain?**  
A: Varies by system. Expect improved frame consistency and reduced stuttering rather than raw FPS increase.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Disclaimer

This tool modifies Windows system settings and removes components. It is provided "as-is" without warranty. The developer is not responsible for any damage, data loss, or system instability. Use at your own risk. Always backup your data before running system modification tools.

## Credits

Made by Sharp4Real  
GitHub: [@sharp4real](https://github.com/sharp4real)

**Remember: Always backup your data before running system optimization tools.**
