# Windows Setup Script

Comprehensive Windows setup and configuration script with automatic detection, software installation, and optimization options.

## Quick Start

### Windows - Interactive Setup Script

```powershell
# Download and run the interactive setup script
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\setup-windows.ps1
```

### Windows - Original Installation Script

```ps
irm https://github.com/LightZirconite/setup-script/raw/main/setupScript.ps1 | iex
```

### Linux - Installation Script

```bash
curl -sSL https://github.com/LightZirconite/setup-script/raw/main/setupScript.sh | sudo bash
```

---

## Interactive Setup Script Features

### Core Capabilities
- ✅ **Automatic Windows Edition Detection** (LTSC/IoT vs Standard Windows 10/11)
- ✅ **Interactive Y/N Prompts** with detailed descriptions for each option
- ✅ **Question Collection Phase** - All questions asked first, installations happen afterward
- ✅ **Error Handling** - Robust error handling with colored output
- ✅ **Administrator Check** - Requires and verifies admin privileges

### Installation Options

#### Office & Activation
- Microsoft Office installation (winget or direct download)
- Windows/Office activation via Microsoft Activation Scripts (MAS)

#### Software via Winget
- Discord (stable, PTB, Canary)
- Steam
- Spotify
- Terminus terminal
- Visual Studio Code
- Firefox
- Python
- Node.js

#### Remote Management
- Mesh Agent with full installation

#### Setup Modes

**Performance Mode:**
- Bulk Crap Uninstaller (deep software removal)
- Rytunex (system optimization)
- Windows LTSC recommendation for maximum performance

**Performance + Enhanced Style Mode:**
- All performance tools
- WinPaletter (Windows theming)
- TranslucentTB (taskbar transparency)
- Files App (modern file manager with taskbar pinning)
- Lively Wallpaper (optional)

#### Device-Specific Tools
- Steam Deck Tools (drivers & fan control)
- Unowhy Tools (device-specific drivers)
- KDE Connect (device connectivity)

#### LTSC/IoT Specific Features
When LTSC/IoT edition is detected, additional options are presented:
- Enable Microsoft Store
- Install Notepad
- Install Windows Terminal
- Install Calculator
- Install Camera app
- Install Media Player
- Install Photos app

#### System Updates
- Update all installed software via winget

## Usage

### Prerequisites
- Windows 10 or Windows 11
- PowerShell 5.1 or higher
- Administrator privileges
- Internet connection

### Running the Script

1. **Open PowerShell as Administrator:**
   - Press `Win + X`
   - Select "Windows PowerShell (Admin)" or "Terminal (Admin)"

2. **Navigate to script directory:**
   ```powershell
   cd "c:\Users\Light\Downloads\setup-script"
   ```

3. **Set execution policy (if needed):**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```

4. **Run the script:**
   ```powershell
   .\setup-windows.ps1
   ```

### Script Flow

1. **Detection Phase**
   - Detects Windows edition (LTSC/IoT or Standard)
   - Displays system information

2. **Configuration Phase**
   - Asks all questions with Y/N prompts
   - Each option includes description
   - Collects all choices before proceeding

3. **Installation Phase**
   - Processes all selected installations
   - Shows progress for each step
   - Handles errors gracefully

4. **Completion**
   - Displays summary
   - Offers system restart option

## Features in Detail

### Windows Edition Detection
The script automatically detects:
- Windows 10/11 LTSC editions
- Windows 10 IoT Enterprise
- Standard Windows editions

This detection enables LTSC-specific features like Microsoft Store installation and default app additions.

### Office Installation Methods

**Winget Method:**
- Fast installation via Windows Package Manager
- Automatic updates integration

**Direct Download:**
- Downloads from official Microsoft CDN
- O365 ProPlus Retail edition
- 64-bit, English (US)

### Activation
Opens Microsoft Activation Scripts in a new PowerShell window with options to activate:
- Windows only
- Office only
- Both Windows and Office

### Performance Mode Tools

**Bulk Crap Uninstaller:**
- Deep uninstallation tool
- Removes leftover files and registry entries
- Auto-downloads latest release from GitHub

**Rytunex:**
- System optimization utility
- Performance tweaks
- Resource management

### Enhanced Style Mode Tools

**WinPaletter:**
- Complete Windows theming solution
- Customize colors, accents, and appearance

**TranslucentTB:**
- Taskbar transparency effects
- Automatic from Microsoft Store

**Files App:**
- Modern file manager
- Replaces Windows Explorer
- Automatic taskbar pinning

**Lively Wallpaper:**
- Animated wallpaper engine
- Video/GIF wallpaper support
- Auto-downloads latest release

### Latest Version Fetching
The script automatically fetches latest versions from GitHub for:
- Bulk Crap Uninstaller
- Lively Wallpaper
- Steam Deck Tools
- KDE Connect

## Safety Features

- Administrator privilege verification
- Comprehensive error handling
- Colored output for clarity (Info/Success/Warning/Error)
- Automatic temp file cleanup
- Safe default choices

## Color Coding

- **Cyan** - Informational messages
- **Green** - Success messages
- **Yellow** - Warnings and prompts
- **Red** - Error messages

## Notes

- Some installations may require manual steps (e.g., Microsoft Store apps)
- Files App pinning to taskbar requires manual action
- Activation script opens in separate window
- System restart recommended after completion
- LTSC users may need to restart after enabling Microsoft Store

## Troubleshooting

**Script won't run:**
- Ensure you're running as Administrator
- Check execution policy: `Get-ExecutionPolicy`
- Use: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process`

**Winget not found:**
- Install App Installer from Microsoft Store
- Or download from: https://github.com/microsoft/winget-cli

**Download failures:**
- Check internet connection
- Verify firewall settings
- Try running script again

**Store apps not installing:**
- Ensure Microsoft Store is enabled (especially on LTSC)
- Check Windows Update is working
- Sign in to Microsoft account

## Version

**Current Version:** 1.0.0

## Requirements

- Windows 10 (1809+) or Windows 11
- PowerShell 5.1+
- Administrator rights
- Active internet connection
- Winget (App Installer) recommended

## License

This script is provided as-is for Windows system setup and configuration purposes.
