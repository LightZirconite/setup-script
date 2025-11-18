# Windows Setup Script

Interactive Windows configuration script with automatic edition detection, software installation, and system optimization.

## Installation

```powershell
irm https://github.com/LightZirconite/setup-script/raw/main/setup-windows.ps1 | iex
```

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1+
- Administrator privileges
- Internet connection
- Winget (App Installer) recommended

## Features

### Automatic Detection
- ✅ Automatically detects Windows edition (LTSC/IoT vs Standard)
- ✅ Enables edition-specific options

### Interactive Mode
- ✅ Y/N questions with detailed descriptions
- ✅ Collects ALL answers BEFORE installing anything
- ✅ Robust error handling with colored output
- ✅ Administrator privilege verification

### Installation Options

#### Office & Activation
- Microsoft Office installation (via winget or direct download)
- Windows/Office activation via Microsoft Activation Scripts

#### Software (winget)
- Discord (stable, PTB, Canary)
- Steam
- Spotify
- Terminus
- Visual Studio Code
- Firefox
- Python
- Node.js

#### Remote Management
- Mesh Agent (with -fullinstall parameter)

#### Configuration Modes

**Performance Mode:**
- Bulk Crap Uninstaller (deep software removal)
- Rytunex (system optimization)
- Windows LTSC recommendation

**Performance + Style Mode:**
- All performance tools
- WinPaletter (Windows theming)
- TranslucentTB (taskbar transparency)
- Files App (modern file manager)
- Lively Wallpaper (optional)

#### Device-Specific Tools
- Steam Deck Tools (drivers and fan control)
- Unowhy Tools (device-specific drivers)
- KDE Connect (device connectivity)

#### LTSC/IoT Options
When LTSC/IoT edition is detected:
- Enable Microsoft Store
- Install Notepad
- Install Windows Terminal
- Install Calculator
- Install Camera
- Install Media Player
- Install Photos

#### System Updates
- Update all software via winget

## Script Flow

### 1. Detection Phase
- Detects Windows edition
- Displays system information

### 2. Configuration Phase
- Asks all questions (Y/N)
- Each option includes a description
- Collects all choices before proceeding

### 3. Installation Phase
- Processes all selected installations
- Shows progress for each step
- Handles errors gracefully

### 4. Completion
- Displays summary
- Offers system restart

## Technical Details

### Office Installation

**Winget Method:**
- Fast installation via Windows Package Manager
- Automatic update integration

**Direct Download:**
- Downloads from official Microsoft CDN
- O365 ProPlus Retail edition
- 64-bit, English (US)

### Version Fetching
The script automatically fetches latest versions via GitHub API for:
- Bulk Crap Uninstaller
- Lively Wallpaper
- Steam Deck Tools
- KDE Connect

### Security
- Administrator privilege verification
- Comprehensive error handling
- Automatic temporary file cleanup
- Safe default choices

### Color Coding
- **Cyan** - Informational messages
- **Green** - Success messages
- **Yellow** - Warnings and prompts
- **Red** - Error messages

## Important Notes

- Some installations require manual steps (Store apps)
- Files App taskbar pinning is manual
- Activation script opens in a new window
- System restart recommended after installation
- LTSC users must restart after enabling Store

## Troubleshooting

**Script won't run:**
```powershell
# Check execution policy
Get-ExecutionPolicy

# Allow execution
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

**Winget not found:**
- Install "App Installer" from Microsoft Store
- Or download from: https://github.com/microsoft/winget-cli

**Download failures:**
- Check internet connection
- Check firewall settings
- Retry the script

**Store apps won't install:**
- Ensure Microsoft Store is enabled (especially on LTSC)
- Check Windows Update is working
- Sign in with a Microsoft account

## Version

**Current Version:** 1.0.0

## License

This script is provided as-is for Windows system setup and configuration purposes.
