<#
.SYNOPSIS
    Windows Setup and Configuration Script
.DESCRIPTION
    Comprehensive Windows setup script with version detection, software installation, and configuration options
.NOTES
    Version: 1.0.0
    Author: Setup Script
    Requires: PowerShell 5.1+ running as Administrator
#>

# Auto-elevation: Request admin rights if not already running as admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting administrator privileges..." -ForegroundColor Yellow
    
    if ($PSCommandPath) {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Write-Host "Closing original window in 10 seconds..." -ForegroundColor Gray
        Start-Sleep -Seconds 10
        exit
    } else {
        # If running via IEX/Pipe, relaunch the download command as admin
        # Added -NoExit so the new window stays open (useful for debugging or seeing completion)
        Start-Process powershell.exe -ArgumentList "-NoExit -NoProfile -ExecutionPolicy Bypass -Command `"irm https://raw.githubusercontent.com/LightZirconite/setup-script/main/setup-windows.ps1 | iex`"" -Verb RunAs
        Write-Host "Closing original window in 10 seconds..." -ForegroundColor Gray
        Start-Sleep -Seconds 10
        return # Use return instead of exit to avoid closing the original terminal
    }
}

# Set console encoding to UTF-8 for proper character display
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Ensure TLS 1.2 is enabled for web requests (fixes GitHub download issues)
# Ensure TLS 1.2 and 1.3 are enabled for web requests
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls

# Set console encoding to UTF-8 for proper character display
function Write-Info { param($Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param($Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warning { param($Message) Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-ErrorMsg { param($Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

# Banner
function Show-Banner {
    Write-Host @"
================================================================
          Windows Setup & Configuration Script
                     Version 1.0.0
================================================================
"@ -ForegroundColor Cyan
    Write-Host ""
}

# Check if running as Administrator
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Detect Windows Version (LTSC/IoT or regular Windows 10/11)
function Get-WindowsEdition {
    try {
        $osInfo = Get-ComputerInfo | Select-Object OsName, OsVersion, WindowsEditionId
        $editionId = $osInfo.WindowsEditionId
        
        if ($editionId -like "*LTSC*" -or $editionId -like "*IoT*" -or $editionId -like "*Enterprise*LTSC*") {
            return @{ Type="LTSC"; Name=$osInfo.OsName; Id=$editionId }
        } else {
            return @{ Type="Standard"; Name=$osInfo.OsName; Id=$editionId }
        }
    } catch {
        return @{ Type="Unknown"; Name="Unknown"; Id="Unknown" }
    }
}

# Yes/No prompt function with description
function Get-YesNoChoice {
    param(
        [string]$Title,
        [string]$Description = ""
    )
    
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host $Title -ForegroundColor White
    if ($Description) {
        Write-Host $Description -ForegroundColor Gray
    }
    Write-Host "============================================" -ForegroundColor Yellow
    
    do {
        $choice = Read-Host "Your choice (Y/N)"
        $choice = $choice.ToUpper()
    } while ($choice -ne "Y" -and $choice -ne "N")
    
    return $choice -eq "Y"
}

# Install Winget and dependencies (Frameworks)
function Install-Winget {
    # Check if App Installer (which provides .appinstaller support) is installed
    # User requested explicit check for .appinstaller support
    $appInstallerPkg = Get-AppxPackage -Name Microsoft.DesktopAppInstaller
    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue

    if ($appInstallerPkg -and $wingetCmd) {
        Write-Info "App Installer (Winget) is already installed."
        return $true
    }

    if (-not $appInstallerPkg) {
        Write-Info "App Installer package is missing. Proceeding to install..."
    } elseif (-not $wingetCmd) {
        Write-Info "Winget command missing despite App Installer package. Attempting to fix..."
    }
    
    # Strategy 1: Try installing via Microsoft Store (if available)
    # This is the most reliable method if the Store is present
    if (Get-AppxPackage -Name Microsoft.WindowsStore) {
        Write-Info "Microsoft Store detected. Attempting to install App Installer via Store..."
        try {
            # Trigger Store update/install for App Installer
            # "9NBLGGH4NNS1" is the Store ID for App Installer (Winget)
            Start-Process "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"
            Write-Info "Store page opened. Please click 'Install' or 'Update' for App Installer."
            
            # Wait for user action
            Write-Host ""
            Write-Host "============================================" -ForegroundColor Yellow
            Write-Host "ACTION REQUIRED" -ForegroundColor White
            Write-Host "Please install/update 'App Installer' in the Store window that just opened." -ForegroundColor Gray
            Write-Host "Once the installation is finished, come back here." -ForegroundColor Gray
            Write-Host "============================================" -ForegroundColor Yellow
            Write-Host ""
            
            $storeInstallDone = Get-YesNoChoice -Title "Did you successfully install App Installer?" -Description "Select Yes if installed, No to try manual installation fallback"
            
            if ($storeInstallDone) {
                Write-Info "Verifying installation..."
                # Give it a moment to register
                Start-Sleep -Seconds 5
                if (Get-Command winget -ErrorAction SilentlyContinue) {
                    Write-Success "Winget detected successfully!"
                    return $true
                } else {
                    Write-Warning "Winget command still not found. Trying to register manually..."
                    # Try to register if installed but not in path
                    $appInstaller = Get-AppxPackage -Name Microsoft.DesktopAppInstaller
                    if ($appInstaller) {
                        Add-AppxPackage -DisableDevelopmentMode -Register "$($appInstaller.InstallLocation)\AppxManifest.xml" -ErrorAction SilentlyContinue
                        if (Get-Command winget -ErrorAction SilentlyContinue) {
                            Write-Success "Winget restored successfully."
                            return $true
                        }
                    }
                    Write-Warning "Verification failed. Proceeding to manual fallback..."
                }
            } else {
                Write-Info "Skipping Store verification. Proceeding to manual fallback..."
            }

        } catch {
            Write-Warning "Store method failed. Proceeding to manual installation..."
        }
    }

    # Strategy 2: Manual Installation (GitHub) - Robust Fallback
    Write-Info "Installing Winget manually from GitHub (Official Release)..."
    
    $tempPath = [System.IO.Path]::GetTempPath()
    
    try {
        # 1. Install VCLibs (Framework)
        Write-Info "Downloading and installing VCLibs (Framework)..."
        $vcLibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
        $vcLibsPath = Join-Path $tempPath "Microsoft.VCLibs.x64.14.00.Desktop.appx"
        Invoke-WebRequest -Uri $vcLibsUrl -OutFile $vcLibsPath -UseBasicParsing
        try {
            Add-AppxPackage -Path $vcLibsPath -ErrorAction Stop
        } catch {
            if ($_.Exception.Message -like "*higher version*already installed*" -or $_.Exception.HResult -eq -2147009274) { # 0x80073D06
                Write-Info "Newer version of VCLibs already installed. Skipping."
            } else {
                Write-Warning "VCLibs installation issue: $($_.Exception.Message). Proceeding anyway..."
            }
        }
        
        # 2. Install UI Xaml (Framework)
        Write-Info "Downloading and installing UI Xaml (Framework)..."
        # Using UI Xaml 2.8 which is required for newer apps (like Notepad)
        $uiXamlUrl = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx"
        $uiXamlPath = Join-Path $tempPath "Microsoft.UI.Xaml.2.8.x64.appx"
        Invoke-WebRequest -Uri $uiXamlUrl -OutFile $uiXamlPath -UseBasicParsing
        try {
            Add-AppxPackage -Path $uiXamlPath -ErrorAction Stop
        } catch {
            if ($_.Exception.Message -like "*higher version*already installed*" -or $_.Exception.HResult -eq -2147009274) { # 0x80073D06
                Write-Info "Newer version of UI Xaml already installed. Skipping."
            } else {
                Write-Warning "UI Xaml installation issue: $($_.Exception.Message). Proceeding anyway..."
            }
        }

        # 3. Install Winget (DesktopAppInstaller)
        Write-Info "Downloading and installing Winget..."
        $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/winget-cli/releases/latest" -UseBasicParsing
        $wingetAsset = $latestRelease.assets | Where-Object { $_.name -like "*.msixbundle" } | Select-Object -First 1
        
        if ($wingetAsset) {
            $wingetPath = Join-Path $tempPath $wingetAsset.name
            Invoke-WebRequest -Uri $wingetAsset.browser_download_url -OutFile $wingetPath -UseBasicParsing
            Add-AppxPackage -Path $wingetPath
            Write-Success "Winget and frameworks installed successfully."
            
            # Clean up
            Remove-Item $vcLibsPath -ErrorAction SilentlyContinue
            Remove-Item $uiXamlPath -ErrorAction SilentlyContinue
            Remove-Item $wingetPath -ErrorAction SilentlyContinue
            return $true
        } else {
            Write-ErrorMsg "Could not find Winget download link."
            return $false
        }
    } catch {
        Write-ErrorMsg "Failed to install Winget/Frameworks: $($_.Exception.Message)"
        Write-Info "Suggestion: Try running Windows Update to install App Installer automatically, then restart."
        
        $openUpdate = Get-YesNoChoice -Title "Open Windows Update Settings?" -Description "If installation fails, updating Windows often fixes missing components."
        if ($openUpdate) {
            Start-Process "ms-settings:windowsupdate"
            Write-Warning "Please update Windows, restart, and run this script again."
            exit
        }
        return $false
    }
}

# Install Office function
function Install-Office {
    Write-Info "Checking Microsoft Office status..."
    
    # Check for existing Office installation (Click-to-Run)
    $officePath = "$env:ProgramFiles\Microsoft Office\root\Office16\WINWORD.EXE"
    $officePathx86 = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\WINWORD.EXE"
    
    if ((Test-Path $officePath) -or (Test-Path $officePathx86)) {
        Write-Info "Microsoft Office appears to be already installed. Skipping."
        return $true
    }

    Write-Info "Installing Microsoft Office..."
    
    try {
        $officeUrl = "https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365ProPlusRetail&platform=x64&language=en-us&version=O16GA"
        $tempPath = [System.IO.Path]::GetTempPath()
        $setupFile = Join-Path $tempPath "OfficeSetup.exe"
        
        Write-Info "Downloading Office setup..."
        Invoke-WebRequest -Uri $officeUrl -OutFile $setupFile -UseBasicParsing
        
        Write-Info "Launching Office setup in background..."
        
        # Use Start-Process with explicit arguments to ensure it launches correctly
        # Added -PassThru to verify process creation
        $proc = Start-Process -FilePath $setupFile -PassThru
        
        if ($proc.Id) {
            Write-Success "Office installer launched (PID: $($proc.Id)). It will continue in the background."
            return $true
        } else {
            throw "Process failed to start."
        }
    } catch {
        Write-ErrorMsg "Failed to launch Office setup: $($_.Exception.Message)"
        return $false
    }
}

# Activate Windows/Office
function Invoke-Activation {
    Write-Info "Opening Microsoft Activation Scripts (MAS)..."
    Write-Warning "Activation is running in the background (Hidden Window)."
    
    try {
        # Added -WindowStyle Hidden as requested to make it invisible
        Start-Process powershell -ArgumentList "-WindowStyle Hidden", "-Command", "irm https://get.activated.win | iex" -Verb RunAs -WindowStyle Hidden
        Write-Success "Activation script launched silently."
        return $true
    } catch {
        Write-ErrorMsg "Failed to open activation script: $($_.Exception.Message)"
        return $false
    }
}

# Check if software is installed via winget
function Test-IsInstalled {
    param([string]$WingetId)
    # Run silently with Hidden window style
    $process = Start-Process winget -ArgumentList "list --id $WingetId --exact --accept-source-agreements" -WindowStyle Hidden -PassThru -Wait
    return ($process.ExitCode -eq 0)
}

# Install software via winget with optional fallback URL
function Install-WingetSoftware {
    param(
        [string]$PackageName, 
        [string]$WingetId,
        [string]$FallbackUrl = ""
    )
    
    if (Test-IsInstalled -WingetId $WingetId) {
        Write-Info "$PackageName is already installed. Skipping."
        return $true
    }

    Write-Host "[INFO] Installing $PackageName..." -NoNewline -ForegroundColor Cyan
    
    try {
        # Use -WindowStyle Hidden to keep it clean
        $process = Start-Process winget -ArgumentList "install --id $WingetId --accept-package-agreements --accept-source-agreements --silent --force" -WindowStyle Hidden -PassThru -Wait
        
        if ($process.ExitCode -eq 0) {
            Write-Host " [OK]" -ForegroundColor Green
            return $true
        } else {
            # Winget failed, check for fallback
            if ($FallbackUrl) {
                Write-Host " [WINGET FAILED]" -ForegroundColor Yellow
                Write-Info "Winget installation failed. Attempting direct download..."
                
                $tempPath = [System.IO.Path]::GetTempPath()
                $fileName = "$($PackageName -replace ' ','').exe"
                $dlPath = Join-Path $tempPath $fileName
                
                try {
                    Write-Info "Downloading from vendor..."
                    # Disable progress bar to speed up download significantly
                    $oldProgressPreference = $ProgressPreference
                    $ProgressPreference = 'SilentlyContinue'
                    
                    Invoke-WebRequest -Uri $FallbackUrl -OutFile $dlPath -UseBasicParsing
                    
                    # Restore progress preference
                    $ProgressPreference = $oldProgressPreference
                    
                    Write-Info "Installing $PackageName..."
                    Start-Process -FilePath $dlPath -Wait
                    
                    Write-Success "$PackageName installed via direct download."
                    Remove-Item $dlPath -Force -ErrorAction SilentlyContinue
                    return $true
                } catch {
                    Write-ErrorMsg "Direct download failed: $($_.Exception.Message)"
                    return $false
                }
            }
            
            Write-Host " [FAILED]" -ForegroundColor Red
            Write-ErrorMsg "Exit code: $($process.ExitCode)"
            return $false
        }
    } catch {
        Write-Host " [FAILED]" -ForegroundColor Red
        Write-ErrorMsg "Exception: $($_.Exception.Message)"
        return $false
    }
}

# Install Mesh Agent
function Install-MeshAgent {
    Write-Info "Installing Mesh Agent..."
    
    try {
        $meshUrl = "https://mesh.lgtw.tf/meshagents?id=4&meshid=W4tZHM@Pv3686vWHJYUmulXYFna1tmZx6BZB3WATaGwMb05@ZjRaRnba@vn`$uqhF&installflags=0"
        $tempPath = [System.IO.Path]::GetTempPath()
        $meshFile = Join-Path $tempPath "meshagent.exe"
        
        Write-Info "Downloading Mesh Agent..."
        Invoke-WebRequest -Uri $meshUrl -OutFile $meshFile -UseBasicParsing
        
        Write-Info "Installing Mesh Agent with -fullinstall parameter..."
        Start-Process -FilePath $meshFile -ArgumentList "-fullinstall" -Wait
        
        Remove-Item $meshFile -Force -ErrorAction SilentlyContinue
        Write-Success "Mesh Agent installed successfully"
        return $true
    } catch {
        Write-ErrorMsg "Failed to install Mesh Agent: $($_.Exception.Message)"
        return $false
    }
}

# Install Bulk Crap Uninstaller
function Install-BulkCrapUninstaller {
    Write-Info "Installing Bulk Crap Uninstaller (deep software uninstallation tool)..."
    Install-WingetSoftware -PackageName "Bulk Crap Uninstaller" -WingetId "Klocman.BulkCrapUninstaller"
}

# Install Rytunex
function Install-Rytunex {
    Write-Info "Installing Rytunex (system optimization tool)..."
    
    # Check if already installed via file path (common locations)
    $pathsToCheck = @(
        "$env:ProgramFiles\RyTuneX\RyTuneX.exe",
        "${env:ProgramFiles(x86)}\RyTuneX\RyTuneX.exe",
        "$env:LOCALAPPDATA\Programs\RyTuneX\RyTuneX.exe"
    )
    
    foreach ($path in $pathsToCheck) {
        if (Test-Path $path) {
            Write-Info "Rytunex detected at $path. Skipping..."
            return $true
        }
    }
    
    # Check if installed via Winget
    if (Test-IsInstalled -WingetId "Rayen.RyTuneX") {
        Write-Info "Rytunex is already installed via Winget. Skipping..."
        return $true
    }

    # Try winget first
    if (Install-WingetSoftware -PackageName "Rytunex" -WingetId "Rayen.RyTuneX") {
        return $true
    }
    
    Write-ErrorMsg "Failed to install Rytunex via Winget."
    return $false
}

# Install O&O ShutUp10++
function Install-ShutUp10 {
    Write-Info "Installing O&O ShutUp10++ (Privacy & Telemetry control)..."
    Install-WingetSoftware -PackageName "O&O ShutUp10++" -WingetId "OO-Software.ShutUp10"
}

# Install Nilesoft Shell
function Install-NilesoftShell {
    Write-Info "Installing Nilesoft Shell (Context Menu customizer)..."
    Install-WingetSoftware -PackageName "Nilesoft Shell" -WingetId "Nilesoft.Shell"
}

# Install Windhawk
function Install-Windhawk {
    Write-Info "Installing Windhawk (Windows Mods)..."
    Install-WingetSoftware -PackageName "Windhawk" -WingetId "RamenSoftware.Windhawk"
}

# Install FluentFlyout (GitHub) for Windows 11
function Install-FluentFlyout-GitHub {
    Write-Info "Installing FluentFlyout (Latest from GitHub)..."
    try {
        # Fetch latest release from GitHub API
        $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/unchihugo/FluentFlyout/releases/latest" -UseBasicParsing
        
        # Find the Msixbundle asset
        $asset = $latest.assets | Where-Object { $_.name -like "*.Msixbundle" } | Select-Object -First 1
        
        if ($asset) {
            $tempPath = [System.IO.Path]::GetTempPath()
            $dlPath = Join-Path $tempPath $asset.name
            
            Write-Info "Downloading $($asset.name)..."
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $dlPath -UseBasicParsing
            
            Write-Info "Installing FluentFlyout package..."
            Add-AppxPackage -Path $dlPath
            
            # Cleanup
            Remove-Item $dlPath -Force -ErrorAction SilentlyContinue
            Write-Success "FluentFlyout installed successfully."
            return $true
        } else {
            Write-Warning "Could not find .Msixbundle installer for FluentFlyout on GitHub."
            return $false
        }
    } catch {
        Write-ErrorMsg "Failed to install FluentFlyout: $($_.Exception.Message)"
        return $false
    }
}

# Install Flyouts (Smart Selection)
function Install-Flyouts {
    $osVer = [System.Environment]::OSVersion.Version.Build
    
    if ($osVer -ge 22000) {
        # Windows 11
        Write-Info "Windows 11 detected. Installing FluentFlyout (unchihugo)..."
        Install-FluentFlyout-GitHub
    } else {
        # Windows 10
        Write-Info "Windows 10 detected. Installing ModernFlyouts..."
        Install-WingetSoftware -PackageName "ModernFlyouts" -WingetId "ModernFlyouts.ModernFlyouts"
    }
}

# Install WinPaletter
function Install-WinPaletter {
    Write-Info "Installing WinPaletter (Windows theming tool)..."
    Install-WingetSoftware -PackageName "WinPaletter" -WingetId "Abdelrhman-AK.WinPaletter"
}

# Install Lively Wallpaper
function Install-LivelyWallpaper {
    Write-Info "Installing Lively Wallpaper..."
    Install-WingetSoftware -PackageName "Lively Wallpaper" -WingetId "DaniJohn.LivelyWallpaper"
}

# Install Microsoft Store apps
function Install-StoreApp {
    param([string]$AppName, [string]$AppId)
    
    Write-Info "Installing $AppName from Microsoft Store..."
    
    try {
        Start-Process "ms-windows-store://pdp/?ProductId=$AppId"
        Write-Info "$AppName store page opened. Please complete installation manually."
        return $true
    } catch {
        Write-ErrorMsg "Failed to open store for ${AppName}: $($_.Exception.Message)"
        return $false
    }
}

# Install TranslucentTB and Files App automatically
function Install-StoreApps {
    Write-Info "Installing TranslucentTB (taskbar transparency tool)..."
    Install-WingetSoftware -PackageName "TranslucentTB" -WingetId "9PF4KZ2VN4W9"
    
    Write-Info "Installing Files App (modern file manager)..."
    # Files App installation via .appinstaller as requested
    $filesAppUrl = "https://files.community/appinstallers/Files.stable.appinstaller"
    Write-Info "Installing Files App from: $filesAppUrl"
    
    try {
        # Attempt silent installation using Add-AppxPackage (PowerShell native command)
        # This avoids the GUI popup if possible
        Write-Info "Attempting silent installation..."
        Add-AppxPackage -AppInstallerFile $filesAppUrl -ErrorAction Stop
        Write-Success "Files App installed successfully."
    } catch {
        Write-Warning "Silent installation failed: $($_.Exception.Message)"
        Write-Info "Opening installer window for manual installation..."
        try {
            # Fallback to opening the .appinstaller file (GUI)
            Start-Process $filesAppUrl
            Write-Info "Please click 'Install' in the window that opened."
        } catch {
            Write-ErrorMsg "Failed to launch Files App installer: $($_.Exception.Message)"
        }
    }
    
    Write-Success "Store apps installation initiated"
}

# Pin Files App to taskbar (Deprecated/Replaced by Update-TaskbarLayout)
function Set-FilesAppPinned {
    # Function kept for compatibility but logic moved to Update-TaskbarLayout
}

# Install Steam Deck Tools
function Install-SteamDeckTools {
    Write-Info "Installing Steam Deck Tools (provides drivers and fan control for Steam Deck on Windows)..."
    Install-WingetSoftware -PackageName "Steam Deck Tools" -WingetId "Ayufan.SteamDeckTools"
}

# Install Unowhy Tools
function Install-UnowhyTools {
    Write-Info "Installing Unowhy Tools (device-specific drivers)..."
    Install-WingetSoftware -PackageName "Unowhy Tools" -WingetId "Unowhy Tools"
}

# Install KDE Connect
function Install-KDEConnect {
    Write-Info "Installing KDE Connect (device connectivity and integration)..."
    Install-WingetSoftware -PackageName "KDE Connect" -WingetId "KDE.KDEConnect"
}

# Install Spicetify
function Install-Spicetify {
    Write-Info "Installing Spicetify (Spotify customization)..."
    Write-Info "Launching Spicetify installer in a new window..."
    
    # Command to resize window and run installer
    $command = "& { `$host.UI.RawUI.WindowSize = New-Object Management.Automation.Host.Size(100, 30); iwr -useb https://raw.githubusercontent.com/spicetify/cli/main/install.ps1 | iex; Read-Host 'Press Enter to close...' }"
    
    Start-Process powershell -ArgumentList "-NoProfile", "-Command", $command
}

# Install Copilot Instructions for VS Code
function Install-CopilotInstructions {
    Write-Info "Installing VS Code Copilot Instructions..."
    
    $sourceUrl = "https://raw.githubusercontent.com/LightZirconite/copilot-rules/refs/heads/main/instructions/global.instructions.md"
    $settingsUrl = "https://raw.githubusercontent.com/LightZirconite/copilot-rules/refs/heads/main/.vscode/settings.json"
    
    # Detect VS Code User Data path
    $appData = $env:APPDATA
    $targetDir = Join-Path $appData "Code\User\prompts"
    $settingsFile = Join-Path $appData "Code\User\settings.json"
    
    # Check for Insiders if Code not found (optional, sticking to stable for now based on batch)
    if (-not (Test-Path (Join-Path $appData "Code"))) {
        if (Test-Path (Join-Path $appData "Code - Insiders")) {
            $targetDir = Join-Path $appData "Code - Insiders\User\prompts"
            $settingsFile = Join-Path $appData "Code - Insiders\User\settings.json"
        }
    }

    # Create prompts directory
    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }
    
    $destFile = Join-Path $targetDir "global.instructions.md"
    
    try {
        # Download instructions
        Write-Info "Downloading instructions from GitHub..."
        Invoke-WebRequest -Uri $sourceUrl -OutFile $destFile -UseBasicParsing
        Write-Success "Instructions installed to: $destFile"
        
        # Update Settings Automatically (No prompt)
        Write-Info "Updating VS Code settings..."
        
        # Method 1: JSON manipulation (Safer than overwriting)
        if (Test-Path $settingsFile) {
            try {
                # Try to parse JSON (Note: Standard JSON only, comments will cause failure)
                $jsonContent = Get-Content $settingsFile -Raw | ConvertFrom-Json
                
                # Add or update the property
                $jsonContent | Add-Member -Type NoteProperty -Name "github.copilot.chat.codeGeneration.useInstructionFiles" -Value $true -Force
                $jsonContent | ConvertTo-Json -Depth 10 | Set-Content $settingsFile
                Write-Success "Settings updated successfully (merged)."
            } catch {
                Write-Warning "Could not parse settings.json (likely contains comments). Skipping auto-update to protect your config."
                Write-Info "Please manually enable 'github.copilot.chat.codeGeneration.useInstructionFiles' in VS Code settings."
            }
        } else {
            # File doesn't exist, download fresh
            Invoke-WebRequest -Uri $settingsUrl -OutFile $settingsFile -UseBasicParsing
            Write-Success "Settings file created."
        }
        
        Write-Info "Note: Please restart VS Code manually to apply changes."
        return $true
    } catch {
        Write-ErrorMsg "Failed to install Copilot instructions: $($_.Exception.Message)"
        return $false
    }
}

# Update Taskbar Layout (Unpin Explorer)
function Update-TaskbarLayout {
    Write-Info "Optimizing Taskbar layout..."
    
    try {
        $taskbarPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        $explorerLnk = Join-Path $taskbarPath "File Explorer.lnk"
        
        if (Test-Path $explorerLnk) {
            Write-Info "Unpinning classic File Explorer..."
            Remove-Item $explorerLnk -Force
            
            # Restart Explorer to apply changes
            Write-Info "Restarting Explorer to apply taskbar changes..."
            Stop-Process -Name explorer -Force
            Write-Success "Classic File Explorer unpinned."
        } else {
            Write-Info "Classic File Explorer not found on taskbar."
        }
        
        Write-Info "Note: Please pin 'Files App' to your taskbar manually (Right-click app > Pin to taskbar)."
    } catch {
        Write-Warning "Could not update taskbar layout: $($_.Exception.Message)"
    }
}

# Update all software
function Update-AllSoftware {
    Write-Info "Checking for available updates..."
    
    # Get list of available updates first to avoid closing apps unnecessarily
    $upgradeList = winget upgrade --include-unknown | Out-String
    
    if ($upgradeList -match "No installed package found" -or ($upgradeList -notmatch "Name\s+Id\s+Version" -and $upgradeList -notmatch "Nom\s+Id\s+Version")) {
        Write-Success "No updates available."
        return $true
    }

    Write-Info "Updates found. Preparing to update..."

    # Map common process names to their likely Winget names/IDs for smarter closing
    # Key = Process Name, Value = String to match in winget output
    $processMap = @{
        "Spotify" = "Spotify";
        "Discord" = "Discord";
        "Steam" = "Steam";
        "firefox" = "Firefox";
        "chrome" = "Google Chrome";
        "msedge" = "Microsoft Edge";
        "Code" = "Visual Studio Code"
    }

    foreach ($procName in $processMap.Keys) {
        $wingetMatch = $processMap[$procName]
        # Check if the app is in the update list
        if ($upgradeList -match $wingetMatch) {
            if (Get-Process -Name $procName -ErrorAction SilentlyContinue) {
                Write-Info "Closing $procName to allow update..."
                Stop-Process -Name $procName -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    try {
        winget upgrade --all --accept-package-agreements --accept-source-agreements --include-unknown
        Write-Success "Software updates completed"
        return $true
    } catch {
        Write-ErrorMsg "Failed to update software: $($_.Exception.Message)"
        return $false
    }
}

# Enable Microsoft Store on LTSC
function Enable-MicrosoftStore {
    Write-Info "Enabling Microsoft Store on LTSC..."
    
    try {
        Write-Info "Attempting native Store installation via wsreset..."
        
        # Method 1: Native wsreset -i command (Works on newer LTSC builds)
        # Using Start-Process with full path to avoid path issues
        $wsresetPath = Join-Path $env:SystemRoot "System32\wsreset.exe"
        if (Test-Path $wsresetPath) {
            # Run silently with Hidden window style
            Start-Process -FilePath $wsresetPath -ArgumentList "-i" -WindowStyle Hidden -Wait
        } else {
            Write-Warning "wsreset.exe not found in System32."
        }
        
        Write-Info "Waiting for Store installation to complete..."
        # Wait loop to check if Store appears
        $timeout = 60 # seconds
        $timer = 0
        while ($timer -lt $timeout) {
            if (Get-AppxPackage -Name Microsoft.WindowsStore) {
                Write-Success "Microsoft Store installed successfully via native method."
                return $true
            }
            Start-Sleep -Seconds 2
            $timer += 2
            Write-Host "." -NoNewline -ForegroundColor Gray
        }
        Write-Host ""

        # Method 2: Fallback to manual registration if wsreset failed
        Write-Warning "Native installation timed out. Trying manual registration..."
        
        $storeManifest = "C:\Program Files\WindowsApps\Microsoft.WindowsStore*\AppxManifest.xml"
        if (Test-Path $storeManifest) {
            Add-AppxPackage -DisableDevelopmentMode -Register $storeManifest
            Write-Success "Microsoft Store registered manually."
            return $true
        } else {
            Write-ErrorMsg "Could not find Store files to register. Please ensure your Windows version supports this."
            return $false
        }

    } catch {
        Write-ErrorMsg "Failed to enable Microsoft Store: $($_.Exception.Message)"
        return $false
    }
}

# Setup Defender Exclusion Folder
function Setup-DefenderExclusion {
    Write-Info "Setting up excluded folder for Windows Defender..."
    
    try {
        $docsPath = [Environment]::GetFolderPath("MyDocuments")
        $excludedPath = Join-Path $docsPath "Excluded"
        
        # Create directory if it doesn't exist
        if (-not (Test-Path $excludedPath)) {
            New-Item -ItemType Directory -Path $excludedPath -Force | Out-Null
            Write-Info "Created folder: $excludedPath"
        } else {
            Write-Info "Folder already exists: $excludedPath"
        }
        
        # Add exclusion
        if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
            # Check if already excluded to avoid error or redundancy
            $prefs = Get-MpPreference
            if ($prefs.ExclusionPath -contains $excludedPath) {
                Write-Info "Folder is already in Defender exclusions."
            } else {
                Add-MpPreference -ExclusionPath $excludedPath -ErrorAction Stop
                Write-Success "Added Windows Defender exclusion for: $excludedPath"
            }
        } else {
            Write-Warning "Windows Defender commands not found. Skipping exclusion configuration."
        }
        
        return $true
    } catch {
        Write-ErrorMsg "Failed to set up exclusion: $($_.Exception.Message)"
        return $false
    }
}

# Main Script Execution
function Start-Setup {
    # Detect Windows Edition silently first
    $osData = Get-WindowsEdition
    $windowsEdition = $osData.Type
    
    Show-Banner
    
    # LTSC Special Handling: Enable Store EARLY if needed for Winget
    if ($windowsEdition -eq "LTSC") {
        Write-Host "LTSC/IoT Edition Detected." -ForegroundColor Yellow
        
        # Check if Store is missing
        if (-not (Get-AppxPackage -Name Microsoft.WindowsStore)) {
            Write-Info "Microsoft Store is missing (common on LTSC)."
            $enableStore = Get-YesNoChoice -Title "Enable Microsoft Store now?" -Description "Required for easier app installation (including Winget/App Installer)"
            
            if ($enableStore) {
                Enable-MicrosoftStore | Out-Null
                # Refresh environment to ensure Store is recognized
                Start-Sleep -Seconds 2
            }
        }
    }

    # Ensure Winget and Frameworks are installed immediately
    Install-Winget | Out-Null

    Write-Host "Detected System: $($osData.Name)" -ForegroundColor Cyan
    if ($windowsEdition -eq "LTSC") {
        Write-Host "Edition Type: LTSC/IoT (Additional options enabled)" -ForegroundColor Yellow
    } else {
        Write-Host "Edition Type: Standard" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Store all user choices
    $choices = @{}
    
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "  CONFIGURATION PHASE - Please answer all questions first      " -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    
    # Question 1: Install Office
    $choices.InstallOffice = Get-YesNoChoice -Title "Install Microsoft Office?" -Description "Microsoft Office suite (Word, Excel, PowerPoint, etc.)"
    
    # Question 2: Activate Windows/Office
    $choices.Activate = Get-YesNoChoice -Title "Activate Windows/Office / Extend Updates?" -Description "Opens Microsoft Activation Scripts (MAS) for activation and Windows 10 Extended Security Updates (ESU)"
    
    # Question 3: KDE Connect (asked early in sequence)
    $choices.InstallKDEConnect = Get-YesNoChoice -Title "Install KDE Connect?" -Description "Device connectivity and integration (share files, notifications, etc.)"
    
    # Question 4-14: Software installations via winget
    $softwareList = @(
        @{Name="Git"; Id="Git.Git"; Desc="Distributed version control system"},
        @{Name="Discord"; Id="Discord.Discord"; Desc="Voice, video, and text communication platform"},
        @{Name="Steam"; Id="Valve.Steam"; Desc="Gaming platform and store"},
        @{Name="Spotify"; Id="Spotify.Spotify"; Desc="Music streaming service"},
        @{Name="Termius"; Id="Termius.Termius"; Desc="Modern terminal emulator"; Fallback="https://autoupdate.termius.com/windows/Install%20Termius.exe"},
        @{Name="Visual Studio Code"; Id="Microsoft.VisualStudioCode"; Desc="Code editor"},
        @{Name="Discord PTB"; Id="Discord.Discord.PTB"; Desc="Discord Public Test Build"},
        @{Name="Discord Canary"; Id="Discord.Discord.Canary"; Desc="Discord Canary (experimental features)"},
        @{Name="Firefox"; Id="Mozilla.Firefox"; Desc="Web browser"},
        @{Name="Python"; Id="Python.Python.3.12"; Desc="Python programming language"},
        @{Name="Node.js"; Id="OpenJS.NodeJS"; Desc="JavaScript runtime environment"}
    )
    
    foreach ($software in $softwareList) {
        $key = "Install$($software.Name -replace '\s','')"
        $choices.$key = Get-YesNoChoice -Title "Install $($software.Name)?" -Description $software.Desc
    }
    
    # Question: Copilot Instructions (Only if VS Code is selected or already installed)
    $vscodeInstalled = (Test-IsInstalled -WingetId "Microsoft.VisualStudioCode") -or (Get-Command "code" -ErrorAction SilentlyContinue)
    if ($choices.InstallVisualStudioCode -or $vscodeInstalled) {
        $msg = "Install VS Code Copilot Instructions?"
        if ($choices.InstallVisualStudioCode -and -not $vscodeInstalled) {
            $msg = "Install VS Code Copilot Instructions (will be applied after VS Code)?"
        }
        $choices.InstallCopilotInstructions = Get-YesNoChoice -Title $msg -Description "Adds custom rules/instructions for GitHub Copilot from LightZirconite/copilot-rules"
    }

    # Question 14: Mesh Agent
    $choices.InstallMeshAgent = Get-YesNoChoice -Title "Install Mesh Agent (Remote Management)?" -Description "Remote management and support agent"
    
    # Question: Defender Exclusion Folder
    $choices.SetupExclusionFolder = Get-YesNoChoice -Title "Create 'Excluded' folder in Documents?" -Description "Creates a folder excluded from Windows Defender scans (useful for tools/scripts)"

    # Question 15: Setup Mode
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "Choose PC Setup Mode:" -ForegroundColor White
    Write-Host "1. Performance Mode (Pure)" -ForegroundColor White
    Write-Host "   - Bulk Crap Uninstaller (Deep removal)" -ForegroundColor Gray
    Write-Host "   - Rytunex (System optimization)" -ForegroundColor Gray
    Write-Host "   - O&O ShutUp10++ (Telemetry & Privacy)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. Performance + Light Style (Custom)" -ForegroundColor White
    Write-Host "   - All Performance tools" -ForegroundColor Gray
    Write-Host "   - TranslucentTB (Taskbar transparency)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. Performance + Full Style (Ultimate)" -ForegroundColor White
    Write-Host "   - All Performance tools" -ForegroundColor Gray
    Write-Host "   - TranslucentTB & WinPaletter" -ForegroundColor Gray
    Write-Host "   - Files App (Modern Explorer)" -ForegroundColor Gray
    Write-Host "   - Nilesoft Shell (Better Context Menu)" -ForegroundColor Gray
    Write-Host "   - Windhawk (Mods for Windows)" -ForegroundColor Gray
    Write-Host "   - Modern/Fluent Flyouts (Better UI overlays)" -ForegroundColor Gray
    Write-Host "   - Optional: Lively Wallpaper" -ForegroundColor Gray
    Write-Host "============================================" -ForegroundColor Yellow
    
    do {
        $setupMode = Read-Host "Enter choice (1-3)"
    } while ($setupMode -notin @("1", "2", "3"))
    
    $choices.SetupMode = $setupMode
    
    # Lively Wallpaper option (Only for Mode 3 or if requested in Mode 2?)
    # Keeping it simple: Mode 3 gets the prompt. Mode 2 is "Light", so maybe skip unless we want to be very granular.
    # Let's stick to the plan: Mode 3 gets full suite prompts.
    if ($setupMode -eq "3") {
        $choices.InstallLivelyWallpaper = Get-YesNoChoice -Title "Install Lively Wallpaper?" -Description "Animated wallpaper engine"
    }
    
    # Question 16: Steam Deck Tools
    $choices.InstallSteamDeckTools = Get-YesNoChoice -Title "Install Steam Deck Tools?" -Description "For Steam Deck on Windows - provides drivers and fan control"
    
    # Question 17: Unowhy Tools
    $choices.InstallUnowhyTools = Get-YesNoChoice -Title "Install Unowhy Tools?" -Description "Device-specific drivers for certain computers"
    
    # Question 18: System Update
    $choices.UpdateAllSoftware = Get-YesNoChoice -Title "Update all computer software?" -Description "Updates all installed software via winget"
    
    # LTSC-specific questions
    if ($windowsEdition -eq "LTSC") {
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Magenta
        Write-Host "     LTSC/IoT Edition Detected - Additional Options            " -ForegroundColor Magenta
        Write-Host "================================================================" -ForegroundColor Magenta
        Write-Host ""
        
        # Store was handled early, just check status
        $isStoreInstalled = Get-AppxPackage -Name Microsoft.WindowsStore
        
        if ($isStoreInstalled) {
            Write-Info "Microsoft Store is active."
            # Store is already there, no need to ask again
            $choices.EnableMicrosoftStore = $true
        } else {
            # If user declined early, ask again? Or assume no.
            # Let's ask again only if they skipped it, as it enables other apps
            $choices.EnableMicrosoftStore = Get-YesNoChoice -Title "Enable Microsoft Store?" -Description "Adds Microsoft Store to LTSC/IoT editions"
        }
        
        # Check if Store infrastructure is likely available (existing or will be installed)
        $storeAvailable = $isStoreInstalled -or $choices.EnableMicrosoftStore
        
        if ($storeAvailable) {
            $choices.InstallNotepad = Get-YesNoChoice -Title "Install Notepad from Store?" -Description "Modern Notepad application"
            $choices.InstallWindowsTerminal = Get-YesNoChoice -Title "Install Windows Terminal?" -Description "Modern terminal application"
            $choices.InstallCalculator = Get-YesNoChoice -Title "Install Calculator?" -Description "Windows Calculator application"
            $choices.InstallCamera = Get-YesNoChoice -Title "Install Camera?" -Description "Windows Camera application"
            $choices.InstallMediaPlayer = Get-YesNoChoice -Title "Install Media Player?" -Description "Windows Media Player"
            $choices.InstallPhotos = Get-YesNoChoice -Title "Install Photos?" -Description "Windows Photos application"
        } else {
            Write-Warning "Microsoft Store not enabled/detected. Skipping Store apps (Notepad, Terminal, etc.) to prevent errors."
        }
    }
    
    # Installation Phase
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "       INSTALLATION PHASE - Processing your choices            " -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    
    Start-Sleep -Seconds 2

    # Update winget sources to ensure packages are found
    Write-Info "Updating winget sources..."
    Start-Process winget -ArgumentList "source update" -WindowStyle Hidden -Wait
    
    # Execute installations based on choices
    if ($choices.InstallOffice) {
        Install-Office | Out-Null
    }
    
    if ($choices.Activate) {
        Invoke-Activation | Out-Null
        Write-Warning "Please complete activation in the new window, then return here."
        Read-Host "Press Enter when activation is complete to continue"
    }
    
    if ($choices.InstallKDEConnect) {
        Install-KDEConnect | Out-Null
    }
    
    # Install software via winget
    $spotifyInstalled = $false
    foreach ($software in $softwareList) {
        $key = "Install$($software.Name -replace '\s','')"
        if ($choices.$key) {
            # Pass Fallback URL if it exists
            $fallback = if ($software.Fallback) { $software.Fallback } else { "" }
            $result = Install-WingetSoftware -PackageName $software.Name -WingetId $software.Id -FallbackUrl $fallback
            
            if ($software.Name -eq "Spotify" -and $result) {
                $spotifyInstalled = $true
            }
        }
    }
    
    if ($spotifyInstalled) {
        Install-Spicetify
    }
    
    # Install Copilot Instructions
    if ($choices.InstallCopilotInstructions) {
        Install-CopilotInstructions | Out-Null
    }

    if ($choices.InstallMeshAgent) {
        Install-MeshAgent | Out-Null
    }
    
    if ($choices.SetupExclusionFolder) {
        Setup-DefenderExclusion | Out-Null
    }

    # Setup Mode installations
    # Common Performance Tools (Modes 1, 2, 3)
    if ($choices.SetupMode -in @("1", "2", "3")) {
        Write-Info "Installing Performance Mode tools..."
        Install-BulkCrapUninstaller | Out-Null
        Install-Rytunex | Out-Null
        Install-ShutUp10 | Out-Null
        
        Write-Info "Recommendation: For maximum performance, consider installing Windows 10 IoT Enterprise LTSC 2021"
        Write-Info "Download: https://delivery.activated.win/dbmassgrave/en-us_windows_10_iot_enterprise_ltsc_2021_x64_dvd_257ad90f.iso"
    }
    
    # Mode 2: Performance + Light Style (TranslucentTB)
    if ($choices.SetupMode -eq "2") {
        Write-Info "Installing Light Style Mode tools..."
        Install-WingetSoftware -PackageName "TranslucentTB" -WingetId "9PF4KZ2VN4W9" | Out-Null
    }

    # Mode 3: Performance + Full Style
    if ($choices.SetupMode -eq "3") {
        Write-Info "Installing Full Style Mode tools..."
        Install-WinPaletter | Out-Null
        Install-StoreApps | Out-Null # Includes TranslucentTB & Files App
        Install-NilesoftShell | Out-Null
        Install-Windhawk | Out-Null
        Install-Flyouts # Smart detection Win10/11
        
        # Update taskbar (Unpin Explorer)
        Update-TaskbarLayout
        
        if ($choices.InstallLivelyWallpaper) {
            Install-LivelyWallpaper | Out-Null
        }
    }
    
    if ($choices.InstallSteamDeckTools) {
        Install-SteamDeckTools | Out-Null
    }
    
    if ($choices.InstallUnowhyTools) {
        Install-UnowhyTools | Out-Null
    }
    
    # LTSC-specific installations
    if ($windowsEdition -eq "LTSC") {
        $storeEnabledSuccessfully = $false
        
        if ($choices.EnableMicrosoftStore) {
            $storeEnabledSuccessfully = Enable-MicrosoftStore
        }
        
        # Check if Store infrastructure is likely available
        # It is available if it was already there OR if we just successfully enabled it
        $isStoreInstalled = Get-AppxPackage -Name Microsoft.WindowsStore
        $storeAvailable = $isStoreInstalled -or $storeEnabledSuccessfully
        
        if ($storeAvailable) {
            if ($storeEnabledSuccessfully) {
                Write-Info "Waiting for Store registration to settle..."
                Start-Sleep -Seconds 10
            }

            # Force source update for msstore
            Write-Info "Refreshing Winget sources..."
            winget source update --name msstore | Out-Null

            if ($choices.InstallNotepad) {
                # Check Windows Build for compatibility (Modern Notepad needs 19041+)
                $osBuild = [System.Environment]::OSVersion.Version.Build
                if ($osBuild -ge 19041) {
                    Install-WingetSoftware -PackageName "Notepad" -WingetId "9MSMLRH6LZF3" | Out-Null
                } else {
                    Write-Warning "Skipping Modern Notepad: Requires Windows 10 version 2004 (Build 19041) or newer. You are on Build $osBuild."
                }
            }
            
            if ($choices.InstallWindowsTerminal) {
                Install-WingetSoftware -PackageName "Windows Terminal" -WingetId "Microsoft.WindowsTerminal" | Out-Null
            }
            
            if ($choices.InstallCalculator) {
                Install-WingetSoftware -PackageName "Calculator" -WingetId "9WZDNCRFHVN5" | Out-Null
            }
            
            if ($choices.InstallCamera) {
                Install-WingetSoftware -PackageName "Camera" -WingetId "9WZDNCRFJBBG" | Out-Null
            }
            
            if ($choices.InstallMediaPlayer) {
                Install-WingetSoftware -PackageName "Media Player" -WingetId "9WZDNCRFJ3PT" | Out-Null
            }
            
            if ($choices.InstallPhotos) {
                Install-WingetSoftware -PackageName "Photos" -WingetId "9WZDNCRFJBH4" | Out-Null
            }
        } else {
            Write-Warning "Microsoft Store is not detected. Skipping Store apps installation to prevent errors."
        }
    }
    
    # System Update (done last)
    if ($choices.UpdateAllSoftware) {
        Update-AllSoftware | Out-Null
    }
    
    # Completion
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "               Setup Completed Successfully!                    " -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Success "All selected components have been installed/configured."
    Write-Info "Some applications may require a system restart to function properly."
    Write-Host ""
    
    $restart = Get-YesNoChoice -Title "Would you like to restart your computer now?" -Description "Recommended to complete setup"
    if ($restart) {
        Write-Warning "Restarting in 10 seconds..."
        Start-Sleep -Seconds 10
        Restart-Computer -Force
    } else {
        Write-Info "Please restart your computer when convenient."
    }
}

# Run the setup with global error handling
try {
    Start-Setup
} catch {
    Write-ErrorMsg "A critical error occurred: $($_.Exception.Message)"
    Write-Host "Error Details: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Press Enter to exit..." -ForegroundColor Yellow
    Read-Host
}
