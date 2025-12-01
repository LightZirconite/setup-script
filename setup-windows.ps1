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
        exit
    } else {
        # If running via IEX/Pipe, relaunch the download command as admin
        Start-Process powershell.exe -ArgumentList "-NoExit -NoProfile -ExecutionPolicy Bypass -Command `"irm https://raw.githubusercontent.com/LightZirconite/setup-script/main/setup-windows.ps1 | iex`"" -Verb RunAs
        exit
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

# Detect Hardware Manufacturer
function Get-HardwareInfo {
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $manufacturer = $computerSystem.Manufacturer
        $model = $computerSystem.Model
        
        $info = @{
            Manufacturer = $manufacturer
            Model = $model
            IsHP = ($manufacturer -like "*HP*" -or $manufacturer -like "*Hewlett*")
            IsUnowhy = ($manufacturer -like "*Unowhy*" -or $model -like "*Y13*")
            IsSteamDeck = ($model -like "*Jupiter*" -or $model -like "*Steam Deck*")
        }
        
        return $info
    } catch {
        return @{ Manufacturer="Unknown"; Model="Unknown"; IsHP=$false; IsUnowhy=$false; IsSteamDeck=$false }
    }
}

# Detect GPU (NVIDIA, AMD, Intel)
function Get-GPUInfo {
    try {
        $gpus = Get-CimInstance -ClassName Win32_VideoController | Select-Object -ExpandProperty Name
        
        $hasNvidia = $false
        $hasAMD = $false
        $hasIntel = $false
        
        foreach ($gpu in $gpus) {
            if ($gpu -like "*NVIDIA*" -or $gpu -like "*GeForce*" -or $gpu -like "*Quadro*" -or $gpu -like "*RTX*" -or $gpu -like "*GTX*") {
                $hasNvidia = $true
            }
            if ($gpu -like "*AMD*" -or $gpu -like "*Radeon*" -or $gpu -like "*ATI*") {
                $hasAMD = $true
            }
            if ($gpu -like "*Intel*" -or $gpu -like "*UHD*" -or $gpu -like "*Iris*" -or $gpu -like "*HD Graphics*") {
                $hasIntel = $true
            }
        }
        
        return @{ HasNVIDIA = $hasNvidia; HasAMD = $hasAMD; HasIntel = $hasIntel; GPUs = $gpus }
    } catch {
        return @{ HasNVIDIA = $false; HasAMD = $false; HasIntel = $false; GPUs = @() }
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
    
    try {
        # Launch in a HIDDEN PowerShell window as requested
        # The user implies MAS opens its own interface or they want it hidden
        Start-Process powershell -ArgumentList "-NoProfile -Command `"irm https://get.activated.win | iex`"" -WindowStyle Hidden
        Write-Success "Activation script launched in background."
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

# Install software via winget with optional fallback URL and Command check
function Install-WingetSoftware {
    param(
        [string]$PackageName, 
        [string]$WingetId,
        [string]$FallbackUrl = "",
        [string]$CheckCommand = ""
    )
    
    # Check via Command (if provided) - Most reliable for CLI tools
    if ($CheckCommand -and (Get-Command $CheckCommand -ErrorAction SilentlyContinue)) {
        Write-Info "$PackageName is already installed (command '$CheckCommand' found). Skipping."
        return $true
    }

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

# Check if software is installed via Registry (Uninstall keys)
function Test-IsInstalledInRegistry {
    param([string]$DisplayNamePattern)
    
    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    
    foreach ($key in $uninstallKeys) {
        if (Test-Path $key) {
            $entries = Get-ChildItem -Path $key -ErrorAction SilentlyContinue
            foreach ($entry in $entries) {
                $name = Get-ItemProperty -Path $entry.PSPath -Name "DisplayName" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName
                if ($name -and $name -match $DisplayNamePattern) {
                    return $true
                }
            }
        }
    }
    return $false
}

# Install Rytunex
function Install-Rytunex {
    Write-Info "Installing Rytunex (system optimization tool)..."
    
    # Check if already installed via file path (common locations)
    $pathsToCheck = @(
        "$env:ProgramFiles\RyTuneX\RyTuneX.exe",
        "${env:ProgramFiles(x86)}\RyTuneX\RyTuneX.exe",
        "$env:LOCALAPPDATA\Programs\RyTuneX\RyTuneX.exe",
        "$env:LOCALAPPDATA\RyTuneX\RyTuneX.exe",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\RyTuneX.lnk",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\RyTuneX.lnk",
        "$env:USERPROFILE\Desktop\RyTuneX.lnk",
        "$env:PUBLIC\Desktop\RyTuneX.lnk"
    )
    
    foreach ($path in $pathsToCheck) {
        if (Test-Path $path) {
            Write-Info "Rytunex detected at $path. Skipping..."
            return $true
        }
    }
    
    # Check via Registry
    if (Test-IsInstalledInRegistry -DisplayNamePattern "RyTuneX") {
        Write-Info "Rytunex detected in Registry. Skipping..."
        return $true
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

# Install Nilesoft Shell
function Install-NilesoftShell {
    Write-Info "Installing Nilesoft Shell (Context Menu customizer)..."
    
    # Check for existing installation
    $shellPath = "$env:ProgramFiles\Nilesoft Shell\bin\shell.exe"
    if (Test-Path $shellPath) {
        Write-Info "Nilesoft Shell is already installed. Skipping."
        return $true
    }
    
    Install-WingetSoftware -PackageName "Nilesoft Shell" -WingetId "Nilesoft.Shell"
}

# Install FluentFlyout (GitHub) for Windows 11
function Install-FluentFlyout-GitHub {
    Write-Info "Installing FluentFlyout (Latest from GitHub)..."
    
    # Check if FluentFlyout is already installed
    $existingApp = Get-AppxPackage | Where-Object { $_.Name -like "*FluentFlyout*" -or $_.PackageFullName -like "*FluentFlyout*" }
    
    if ($existingApp) {
        Write-Info "FluentFlyout is already installed ($($existingApp.Name)). Skipping."
        return $true
    }
    
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

# Install Lively Wallpaper
function Install-LivelyWallpaper {
    Write-Info "Installing Lively Wallpaper..."
    Install-WingetSoftware -PackageName "Lively Wallpaper" -WingetId "DaniJohn.LivelyWallpaper"
}


# Apply Windows 11 Theme Pack
function Apply-Windows11Theme {
    Write-Info "Applying Windows 11 theme pack..."
    
    try {
        # Check if Windows 11 theme is already applied
        $currentTheme = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes" -Name "CurrentTheme" -ErrorAction SilentlyContinue
        if ($currentTheme -and $currentTheme.CurrentTheme -like "*Windows-11*") {
            Write-Info "Windows 11 theme is already applied. Skipping."
            return $true
        }
        
        $tempPath = [System.IO.Path]::GetTempPath()
        $themeFile = Join-Path $tempPath "Windows-11.deskthemepack"
        
        Write-Info "Downloading Windows 11 theme pack..."
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/LightZirconite/setup-script/main/Windows-11.deskthemepack" -OutFile $themeFile -UseBasicParsing
        
        Write-Info "Applying theme..."
        Start-Process -FilePath $themeFile -Wait
        
        Write-Info "Switching to dark mode..."
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0 -Type DWord -Force
        
        Write-Info "Closing Settings window..."
        Get-Process | Where-Object { $_.ProcessName -eq "SystemSettings" } | Stop-Process -Force -ErrorAction SilentlyContinue
        
        Remove-Item $themeFile -ErrorAction SilentlyContinue
        Write-Success "Windows 11 theme pack applied successfully in dark mode."
        
        return $true
    } catch {
        Write-ErrorMsg "Failed to apply Windows 11 theme: $($_.Exception.Message)"
        return $false
    }
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

# Install TranslucentTB
function Install-TranslucentTB {
    Write-Info "Installing TranslucentTB (taskbar transparency tool)..."
    Install-WingetSoftware -PackageName "TranslucentTB" -WingetId "9PF4KZ2VN4W9"
}

# Install Files App
function Install-FilesApp {
    Write-Info "Installing Files App (modern file manager)..."
    
    try {
        $tempPath = [System.IO.Path]::GetTempPath()
        $appInstallerFile = Join-Path $tempPath "Files.stable.appinstaller"
        
        Write-Info "Downloading Files App installer..."
        Invoke-WebRequest -Uri "https://files.community/appinstallers/Files.stable.appinstaller" -OutFile $appInstallerFile -UseBasicParsing
        
        Write-Info "Installing Files App..."
        try {
            Add-AppxPackage -AppInstallerFile $appInstallerFile -ErrorAction Stop
            Write-Success "Files App installed successfully."
            return $true
        } catch {
            Write-Warning "Silent installation failed. Opening installer for manual installation..."
            Start-Process $appInstallerFile
            Write-Info "Please click 'Install' in the window that opened."
            return $true
        }
        
        Remove-Item $appInstallerFile -ErrorAction SilentlyContinue
    } catch {
        Write-ErrorMsg "Failed to download/install Files App: $($_.Exception.Message)"
        return $false
    }
}

# Install NVIDIA Drivers
function Install-NVIDIADrivers {
    Write-Info "Checking if NVIDIA software is already installed..."
    
    # Check if NVIDIA GeForce Experience or NVIDIA App is installed
    $nvidiaApp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*NVIDIA*" -and ($_.DisplayName -like "*GeForce Experience*" -or $_.DisplayName -like "*NVIDIA App*") }
    
    if ($nvidiaApp) {
        Write-Info "NVIDIA software is already installed. Skipping."
        return $true
    }
    
    Write-Info "Installing NVIDIA App (GPU drivers and control panel)..."
    
    # Try winget first
    if (Install-WingetSoftware -PackageName "NVIDIA App" -WingetId "Nvidia.GeForceExperience") {
        return $true
    }
    
    # Fallback: Open NVIDIA download page
    Write-Warning "Winget installation failed. Opening NVIDIA download page..."
    try {
        Start-Process "https://www.nvidia.com/en-us/software/nvidia-app/"
        Write-Info "Please download and install NVIDIA App from the opened page."
        return $true
    } catch {
        Write-ErrorMsg "Failed to open NVIDIA page: $($_.Exception.Message)"
        return $false
    }
}

# Install AMD Drivers
function Install-AMDDrivers {
    Write-Info "Checking if AMD software is already installed..."
    
    # Check if AMD Adrenalin or AMD Software is installed
    $amdApp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*AMD*" -and ($_.DisplayName -like "*Adrenalin*" -or $_.DisplayName -like "*Software*" -or $_.DisplayName -like "*Radeon*") }
    
    if ($amdApp) {
        Write-Info "AMD software is already installed. Skipping."
        return $true
    }
    
    Write-Info "Installing AMD Adrenalin (GPU drivers and control panel)..."
    
    # Try winget first
    if (Install-WingetSoftware -PackageName "AMD Software" -WingetId "AMD.AMDSoftware") {
        return $true
    }
    
    # Fallback: Open AMD download page
    Write-Warning "Winget installation failed. Opening AMD download page..."
    try {
        Start-Process "https://www.amd.com/en/support"
        Write-Info "Please download and install AMD Software from the opened page."
        return $true
    } catch {
        Write-ErrorMsg "Failed to open AMD page: $($_.Exception.Message)"
        return $false
    }
}

# Install Intel Drivers (Driver & Support Assistant)
function Install-IntelDrivers {
    Write-Info "Checking if Intel Driver & Support Assistant is already installed..."
    
    # Check if already installed
    $intelDSA = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Intel*Driver*Support*" -or $_.DisplayName -like "*Intel DSA*" }
    
    if ($intelDSA) {
        Write-Info "Intel Driver & Support Assistant is already installed."
        Write-Info "Opening Intel Support page to check for updates..."
        Start-Process "https://www.intel.com/content/www/us/en/support/detect.html"
        return $true
    }
    
    Write-Info "Installing Intel Driver & Support Assistant..."
    
    try {
        $tempPath = [System.IO.Path]::GetTempPath()
        $installerPath = Join-Path $tempPath "Intel-DSA-Installer.exe"
        
        Write-Info "Downloading Intel Driver & Support Assistant..."
        Invoke-WebRequest -Uri "https://dsadata.intel.com/installer" -OutFile $installerPath -UseBasicParsing
        
        Write-Info "Running Intel installer..."
        Start-Process -FilePath $installerPath -Wait
        
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        Write-Success "Intel Driver & Support Assistant installed successfully."
        
        Write-Info "Opening Intel Support page..."
        Start-Process "https://www.intel.com/content/www/us/en/support/detect.html"
        
        return $true
    } catch {
        Write-ErrorMsg "Failed to install Intel drivers: $($_.Exception.Message)"
        Write-Info "You can manually download from: https://www.intel.com/content/www/us/en/support/detect.html"
        return $false
    }
}

# Install Intel Graphics Software (Modern Intel GPU Control Panel)
function Install-IntelGraphicsSoftware {
    Write-Info "Checking if Intel Graphics Software is already installed..."
    
    # Check ONLY for the modern Intel Graphics Software (IntelGraphicsExperience)
    # Do NOT consider the old Command Center as a valid substitute
    $intelGS = Get-AppxPackage | Where-Object { $_.Name -like "*IntelGraphicsExperience*" }
    
    if ($intelGS) {
        Write-Info "Intel Graphics Software is already installed. Skipping."
        return $true
    }
    
    # Check if old Command Center is present (warn user but proceed with new install)
    $oldCommandCenter = Get-AppxPackage | Where-Object { $_.Name -like "*IntelGraphicsCommandCenter*" }
    if ($oldCommandCenter) {
        Write-Warning "Old Intel Graphics Command Center detected. Installing the newer Intel Graphics Software..."
    }
    
    Write-Info "Installing Intel Graphics Software (Modern GPU Control Panel)..."
    
    # Try winget first with the modern Graphics Software Store ID
    Install-WingetSoftware -PackageName "Intel Graphics Software" -WingetId "9P8K5G2MWW6Z"
    
    # Verify installation
    $intelGS = Get-AppxPackage | Where-Object { $_.Name -like "*IntelGraphicsExperience*" }
    
    if ($intelGS) {
        Write-Success "Intel Graphics Software installed successfully."
        return $true
    }
    
    # Fallback: Open Microsoft Store page if Appx is still missing
    Write-Warning "Appx package not detected (Winget might have failed or it needs manual install)."
    Write-Info "Opening Microsoft Store page..."
    try {
        Start-Process "ms-windows-store://pdp/?ProductId=9P8K5G2MWW6Z"
        Write-Info "Please install Intel Graphics Software from the Store."
        return $true
    } catch {
        Write-ErrorMsg "Failed to open Store: $($_.Exception.Message)"
        return $false
    }
}

# Open HP Driver Detection Page
function Install-HPDrivers {
    Write-Info "Opening HP Driver Support page..."
    try {
        Start-Process "https://support.hp.com/drivers"
        Write-Success "HP Driver page opened. The site will auto-detect your PC model."
        return $true
    } catch {
        Write-ErrorMsg "Failed to open HP page: $($_.Exception.Message)"
        return $false
    }
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

# --- NEW FEATURES START ---

# Automated BIOS/Driver Updates
function Install-BiosUpdates {
    param([hashtable]$HardwareInfo)
    
    Write-Info "Checking for BIOS and Driver updates..."
    
    if ($HardwareInfo.Manufacturer -like "*Dell*") {
        Write-Info "Dell system detected. Installing Dell Command | Update..."
        if (Install-WingetSoftware -PackageName "Dell Command | Update" -WingetId "Dell.CommandUpdate") {
            Write-Info "Running Dell Command | Update CLI..."
            try {
                # Attempt to find the CLI executable
                $dcuPath = "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
                if (-not (Test-Path $dcuPath)) {
                    $dcuPath = "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"
                }
                
                if (Test-Path $dcuPath) {
                    Write-Info "Scanning for updates (this may take a while)..."
                    Start-Process -FilePath $dcuPath -ArgumentList "/applyUpdates -silent" -Wait
                    Write-Success "Dell updates applied."
                } else {
                    Write-Warning "Dell Command | Update CLI not found. Please run the application manually."
                }
            } catch {
                Write-ErrorMsg "Failed to run Dell updates: $($_.Exception.Message)"
            }
        }
    }
    elseif ($HardwareInfo.Manufacturer -like "*Lenovo*") {
        Write-Info "Lenovo system detected. Installing Lenovo System Update..."
        if (Install-WingetSoftware -PackageName "Lenovo System Update" -WingetId "Lenovo.SystemUpdate") {
            Write-Info "Launching Lenovo System Update..."
            try {
                # Lenovo System Update usually requires user interaction for the first run or specific CLI flags
                # tvsu.exe is the main executable
                $tvsuPath = "${env:ProgramFiles(x86)}\Lenovo\System Update\tvsu.exe"
                if (Test-Path $tvsuPath) {
                    Start-Process -FilePath $tvsuPath
                    Write-Success "Lenovo System Update launched. Please follow the on-screen instructions."
                } else {
                    Write-Warning "Lenovo System Update executable not found."
                }
            } catch {
                Write-ErrorMsg "Failed to launch Lenovo updates: $($_.Exception.Message)"
            }
        }
    }
    elseif ($HardwareInfo.IsHP) {
        Write-Info "HP system detected. Opening HP Driver Support page..."
        Start-Process "https://support.hp.com/drivers"
        Write-Success "HP Driver page opened."
    }
    else {
        Write-Info "Generic or unknown manufacturer ($($HardwareInfo.Manufacturer)). Opening Windows Update..."
        Start-Process "ms-settings:windowsupdate"
        Write-Info "Please check for 'Optional Updates' in Windows Update for BIOS/Firmware."
    }
}

# Win11Debloat Integration
function Invoke-Win11Debloat {
    param(
        [string]$Mode = "TweaksOnly" # Options: "Full" (Removes Apps), "TweaksOnly" (Keeps Apps)
    )
    
    Write-Info "Preparing to run Win11Debloat ($Mode)..."
    
    try {
        # Define the command based on mode
        # -RunDefaults: Removes apps + Tweaks
        # -RunDefaultsLite: Tweaks only (No app removal)
        
        $params = if ($Mode -eq "Full") { "-RunDefaults" } else { "-RunDefaultsLite" }
        
        Write-Info "Downloading and executing Win11Debloat with $params..."
        
        # We use the "Quick method" command style but with our parameters
        # Using a new PowerShell process to ensure clean execution environment
        $scriptCmd = "iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Raphire/Win11Debloat/master/Win11Debloat.ps1'))"
        
        # Construct the full command to run in a separate process
        # We download the script to a temp file to run it with parameters reliably
        $tempPath = [System.IO.Path]::GetTempPath()
        $debloatScript = Join-Path $tempPath "Win11Debloat.ps1"
        
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Raphire/Win11Debloat/master/Win11Debloat.ps1" -OutFile $debloatScript -UseBasicParsing
        
        Write-Info "Running script..."
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$debloatScript`" $params" -Wait
        
        Remove-Item $debloatScript -ErrorAction SilentlyContinue
        Write-Success "Win11Debloat execution completed."
        return $true
        
    } catch {
        Write-ErrorMsg "Failed to run Win11Debloat: $($_.Exception.Message)"
        return $false
    }
}

# Gaming Stack (Visual C++ & DirectX & Optimizations)
function Install-GamingStack {
    Write-Info "Installing Gaming Stack (Runtimes & Optimizations)..."
    
    # 1. Visual C++ Redistributables (AIO or Latest)
    # Installing the latest supported 2015-2022 redist is usually enough for modern games
    Write-Info "Installing Visual C++ 2015-2022 Redistributable..."
    Install-WingetSoftware -PackageName "Visual C++ 2015-2022 Redist" -WingetId "Microsoft.VCRedist.2015+.x64"
    
    # 2. DirectX
    # Winget has a DirectX Runtime package
    Write-Info "Installing DirectX End-User Runtime..."
    Install-WingetSoftware -PackageName "DirectX Runtime" -WingetId "Microsoft.DirectX"
    
    # 3. Game Mode Optimization
    Write-Info "Enabling Windows Game Mode..."
    try {
        $regPath = "HKCU:\Software\Microsoft\GameBar"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        # AllowAutoGameMode = 1 (On)
        Set-ItemProperty -Path $regPath -Name "AllowAutoGameMode" -Value 1 -Type DWord -Force
        
        # High Performance Power Plan (Ultimate Performance if available, otherwise High Performance)
        # This is a bit aggressive, maybe just ensure High Performance is available
        # powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 (Ultimate Performance)
        
        Write-Success "Game Mode enabled."
    } catch {
        Write-Warning "Could not set Game Mode registry key."
    }
}

# WSL Setup
function Install-WSL {
    Write-Info "Setting up Windows Subsystem for Linux (WSL)..."
    
    if (Get-Command wsl -ErrorAction SilentlyContinue) {
        Write-Info "WSL command detected. Checking status..."
        $wslStatus = wsl --status | Out-String
        if ($wslStatus -match "Default Distribution") {
            Write-Info "WSL appears to be already installed and configured."
            return $true
        }
    }
    
    Write-Info "Installing WSL (this will require a restart)..."
    try {
        # wsl --install installs Ubuntu by default
        Start-Process "wsl" -ArgumentList "--install" -Wait
        Write-Success "WSL installation command executed."
        Write-Warning "A system restart is REQUIRED to complete WSL installation."
    } catch {
        Write-ErrorMsg "Failed to run WSL install: $($_.Exception.Message)"
    }
}

# Install Nerd Fonts
function Install-NerdFonts {
    Write-Info "Installing MesloLGS Nerd Font (for modern terminal icons)..."
    Install-WingetSoftware -PackageName "MesloLGS NF" -WingetId "RyanLlamas.MesloLGSNF"
}

# Setup Ultimate Performance Power Plan
function Setup-PowerPlan {
    Write-Info "Setting up 'Ultimate Performance' power plan..."
    try {
        # Duplicate the Ultimate Performance scheme
        $output = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 2>&1
        
        if ($output -match "([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})") {
            $newGuid = $matches[1]
            Write-Info "Ultimate Performance plan created (GUID: $newGuid)."
            powercfg -setactive $newGuid
            Write-Success "Power plan set to Ultimate Performance."
        } else {
            Write-Warning "Could not create Ultimate Performance plan. Trying High Performance..."
            powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        }
    } catch {
        Write-ErrorMsg "Failed to set power plan: $($_.Exception.Message)"
    }
}

# --- NEW FEATURES END ---

# Install KDE Connect
function Install-KDEConnect {
    Write-Info "Installing KDE Connect (device connectivity and integration)..."
    Install-WingetSoftware -PackageName "KDE Connect" -WingetId "KDE.KDEConnect"
}

# Install Spotify from official source
function Install-Spotify {
    Write-Info "Checking if Spotify is already installed..."
    
    # Check common Spotify installation paths
    $spotifyPaths = @(
        "$env:APPDATA\Spotify\Spotify.exe",
        "$env:LOCALAPPDATA\Microsoft\WindowsApps\Spotify.exe"
    )
    
    $spotifyInstalled = $false
    foreach ($path in $spotifyPaths) {
        if (Test-Path $path) {
            Write-Info "Spotify detected at $path."
            $spotifyInstalled = $true
            break
        }
    }
    
    if (-not $spotifyInstalled) {
        Write-Info "Installing Spotify from official source..."
        try {
            $tempPath = [System.IO.Path]::GetTempPath()
            $spotifySetup = Join-Path $tempPath "SpotifySetup.exe"
            
            Write-Info "Downloading Spotify installer..."
            Invoke-WebRequest -Uri "https://download.scdn.co/SpotifySetup.exe" -OutFile $spotifySetup -UseBasicParsing
            
            Write-Info "Running Spotify installer (as regular user)..."
            
            # Use Shell.Application to launch the installer. 
            # This is the most reliable way to de-escalate to the logged-in user's privileges.
            $shell = New-Object -ComObject Shell.Application
            $shell.ShellExecute($spotifySetup)
            
            Write-Warning "Please complete the Spotify installation in the new window."
            Read-Host "Press Enter when Spotify installation is complete to continue"
            
            Remove-Item $spotifySetup -Force -ErrorAction SilentlyContinue
            Write-Success "Spotify installation step completed."
        } catch {
            Write-ErrorMsg "Failed to install Spotify: $($_.Exception.Message)"
            return $false
        }
    }
    
    return $true
}

# Install Spicetify
function Install-Spicetify {
    Write-Info "Installing Spicetify (Spotify customization)..."
    
    # Check if Spicetify is already installed
    if (Test-Path "$env:LOCALAPPDATA\spicetify\spicetify.exe") {
        Write-Info "Spicetify is already installed. Skipping..."
        return
    }
    
    Write-Info "Launching Spicetify installer in a new window (as non-admin user)..."
    
    try {
        $tempPath = [System.IO.Path]::GetTempPath()
        $batchFile = Join-Path $tempPath "install_spicetify.bat"
        
        # Create a batch file to run the PowerShell command
        # This ensures it runs in a new window and keeps it open
        $batchContent = @"
@echo off
title Spicetify Installer
echo Installing Spicetify...
powershell -NoProfile -Command "iwr -useb https://raw.githubusercontent.com/spicetify/cli/main/install.ps1 | iex"
echo.
echo Installation complete.
pause
"@
        Set-Content -Path $batchFile -Value $batchContent
        
        # Launch the batch file using runas /trustlevel:0x20000 to force de-escalation
        # This ensures the PowerShell session inside runs as a standard user
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c runas /trustlevel:0x20000 `"$batchFile`""
        
        Write-Success "Spicetify installer launched as regular user."
        Write-Warning "Please wait for the Spicetify installation window to finish."
        
        # Clean up batch file after a delay (to allow it to start)
        Start-Sleep -Seconds 5
        # We can't delete it immediately if it's running, but it's in temp so it's fine.
    } catch {
        Write-ErrorMsg "Failed to launch Spicetify installer: $($_.Exception.Message)"
    }
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

# Update all software
function Update-AllSoftware {
    Write-Info "Checking for available updates..."
    
    # Get list of available updates first to avoid closing apps unnecessarily
    $upgradeList = winget upgrade --include-unknown | Out-String
    
    if ($upgradeList -match "No installed package found" -or ($upgradeList -notmatch "Name\s+Id\s+Version" -and $upgradeList -notmatch "Nom\s+Id\s+Version")) {
        Write-Success "No updates available. All software is up to date."
        return $true
    }

    Write-Host ""
    Write-Host "Available updates:" -ForegroundColor Yellow
    Write-Host $upgradeList -ForegroundColor Gray
    Write-Host ""
    
    Write-Info "Preparing to update packages..."

    # Get all running processes that might need updating
    $runningProcesses = Get-Process | Select-Object -ExpandProperty Name -Unique
    
    # Map common app names to their process variations
    $appProcessMap = @{
        "Discord" = @("Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment");
        "Spotify" = @("Spotify", "SpotifyWebHelper");
        "Steam" = @("Steam");
        "Firefox" = @("firefox");
        "Chrome" = @("chrome");
        "Edge" = @("msedge", "MicrosoftEdge");
        "VSCode" = @("Code");
        "Notepad" = @("notepad++");
        "Termius" = @("Termius")
    }
    
    $closedApps = @()
    foreach ($appName in $appProcessMap.Keys) {
        $escapedAppName = [regex]::Escape($appName)
        if ($upgradeList -match $escapedAppName) {
            $processNames = $appProcessMap[$appName]
            foreach ($procName in $processNames) {
                if ($runningProcesses -contains $procName) {
                    Write-Info "Closing $procName to allow update..."
                    Stop-Process -Name $procName -Force -ErrorAction SilentlyContinue
                    $closedApps += $procName
                }
            }
        }
    }
    
    if ($closedApps.Count -gt 0) {
        Write-Info "Closed $($closedApps.Count) running application(s) for update."
    }
    
    Write-Host ""
    Write-Info "Starting update process... (this may take a few minutes)"
    Write-Host ""
    
    try {
        # Run winget directly without capturing output to preserve progress bars and avoid encoding issues
        $process = Start-Process winget -ArgumentList "upgrade --all --accept-package-agreements --accept-source-agreements --include-unknown" -NoNewWindow -PassThru -Wait
        
        if ($process.ExitCode -eq 0) {
            Write-Success "Update process completed successfully."
            return $true
        } else {
            Write-Warning "Update process completed with exit code: $($process.ExitCode)"
            return $false
        }
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
    
    # Question 2.5: Win11Debloat
    $runDebloat = Get-YesNoChoice -Title "Run Complete Windows Debloat?" -Description "Removes bloatware (Candy Crush, etc.) AND disables Telemetry/Tracking/Bing. (Recommended)"
    
    if ($runDebloat) {
        $choices.DebloatMode = "Full"
    } else {
        $choices.DebloatMode = "None"
    }

    # Question 3: Setup Mode Selection
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "Setup Mode Selection" -ForegroundColor White
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "1. Custom Light Mode (Recommended)" -ForegroundColor Cyan
    Write-Host "   Pre-selects popular apps: Git, Discord, Steam, Spotify," -ForegroundColor Gray
    Write-Host "   Termius, VS Code, Python, Node.js" -ForegroundColor Gray
    Write-Host "   + System tools: Rytunex, TranslucentTB, Nilesoft Shell" -ForegroundColor Gray
    Write-Host "   (All other options will be asked individually)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "2. Manual Selection" -ForegroundColor White
    Write-Host "   Choose each software individually" -ForegroundColor Gray
    Write-Host "============================================" -ForegroundColor Yellow
    
    do {
        $setupChoice = Read-Host "Enter choice (1-2)"
    } while ($setupChoice -notin @("1", "2"))
    
    $useCustomLight = ($setupChoice -eq "1")
    
    # Initialize software list for tracking
    $softwareList = @(
        @{Name="Git"; Id="Git.Git"; Desc="Distributed version control system"; Command="git"},
        @{Name="Discord"; Id="Discord.Discord"; Desc="Voice, video, and text communication platform"},
        @{Name="Steam"; Id="Valve.Steam"; Desc="Gaming platform and store"},
        @{Name="Spotify"; Id="Spotify.Spotify"; Desc="Music streaming service"},
        @{Name="Termius"; Id="Termius.Termius"; Desc="Modern terminal emulator"; Fallback="https://autoupdate.termius.com/windows/Install%20Termius.exe"},
        @{Name="Visual Studio Code"; Id="Microsoft.VisualStudioCode"; Desc="Code editor"; Command="code"},
        @{Name="Discord PTB"; Id="Discord.Discord.PTB"; Desc="Discord Public Test Build"},
        @{Name="Discord Canary"; Id="Discord.Discord.Canary"; Desc="Discord Canary (experimental features)"},
        @{Name="Firefox"; Id="Mozilla.Firefox"; Desc="Web browser"},
        @{Name="Python"; Id="Python.Python.3.12"; Desc="Python programming language"; Command="python"},
        @{Name="Node.js"; Id="OpenJS.NodeJS"; Desc="JavaScript runtime environment"; Command="node"}
    )
    
    # Custom Light Mode: Pre-select specific software
    if ($useCustomLight) {
        Write-Host ""
        Write-Info "Custom Light Mode: Pre-selecting recommended software..."
        
        # Pre-select software
        foreach ($software in $softwareList) {
            $key = "Install$($software.Name -replace '\s','')"
            # Pre-select: Git, Discord, Steam, Spotify, Termius, VS Code, Python, Node.js
            if ($software.Name -in @("Git", "Discord", "Steam", "Spotify", "Termius", "Visual Studio Code", "Python", "Node.js")) {
                $choices.$key = $true
            } else {
                $choices.$key = $false
            }
        }
        
        # Pre-select system tools
        $choices.InstallRytunex = $true
        $choices.InstallTranslucentTB = $true
        $choices.InstallNilesoftShell = $true
        $choices.InstallGamingStack = $true
        $choices.SetupPowerPlan = $true
        $choices.InstallNerdFonts = $true
        
        # Display all pre-selected items
        Write-Host ""
        Write-Host "Pre-selected in Custom Light Mode:" -ForegroundColor Green
        Write-Host ""
        Write-Host "Software:" -ForegroundColor Cyan
        foreach ($software in $softwareList) {
            $key = "Install$($software.Name -replace '\s','')"
            if ($choices.$key) {
                Write-Host "  ✓ $($software.Name)" -ForegroundColor White
            }
        }
        Write-Host ""
        Write-Host "System Tools:" -ForegroundColor Cyan
        Write-Host "  ✓ Rytunex (System optimization)" -ForegroundColor White
        Write-Host "  ✓ TranslucentTB (Taskbar transparency)" -ForegroundColor White
        Write-Host "  ✓ Nilesoft Shell (Context Menu)" -ForegroundColor White
        Write-Host "  ✓ Gaming Stack (VC++ / DirectX / Game Mode)" -ForegroundColor White
        Write-Host "  ✓ Ultimate Performance Power Plan" -ForegroundColor White
        Write-Host "  ✓ Nerd Fonts (MesloLGS NF)" -ForegroundColor White
        
        # Ask if user wants to modify selection (ONE TIME)
        Write-Host ""
        $modifySelection = Get-YesNoChoice -Title "Modify Custom Light selection?" -Description "You can customize which software and tools to install"
        
        if ($modifySelection) {
            Write-Host ""
            Write-Host "============================================" -ForegroundColor Yellow
            Write-Host "Customize Installation" -ForegroundColor White
            Write-Host "============================================" -ForegroundColor Yellow
            
            # Show current selection and allow toggling
            foreach ($software in $softwareList) {
                $key = "Install$($software.Name -replace '\s','')"
                $currentStatus = if ($choices.$key) { "[SELECTED]" } else { "[NOT SELECTED]" }
                $statusColor = if ($choices.$key) { "Green" } else { "Gray" }
                
                Write-Host ""
                Write-Host "$currentStatus $($software.Name)" -ForegroundColor $statusColor -NoNewline
                Write-Host " - $($software.Desc)" -ForegroundColor Gray
                
                $toggle = Get-YesNoChoice -Title "Install $($software.Name)?" -Description "Current: $currentStatus"
                $choices.$key = $toggle
            }
            
            # System tools modification
            Write-Host ""
            Write-Host "System Tools:" -ForegroundColor Cyan
            $choices.InstallRytunex = Get-YesNoChoice -Title "Install Rytunex?" -Description "System optimization tool [SELECTED]"
            $choices.InstallTranslucentTB = Get-YesNoChoice -Title "Install TranslucentTB?" -Description "Taskbar transparency tool [SELECTED]"
            $choices.InstallNilesoftShell = Get-YesNoChoice -Title "Install Nilesoft Shell?" -Description "Context Menu customizer [SELECTED]"
            $choices.InstallGamingStack = Get-YesNoChoice -Title "Install Gaming Stack?" -Description "Visual C++ / DirectX / Game Mode [SELECTED]"
            $choices.SetupPowerPlan = Get-YesNoChoice -Title "Enable Ultimate Performance?" -Description "Power Plan [SELECTED]"
            $choices.InstallNerdFonts = Get-YesNoChoice -Title "Install Nerd Fonts?" -Description "Terminal Icons [SELECTED]"
        }
        
        # Ask for KDE Connect separately (not in preset)
        Write-Host ""
        Write-Host "Additional software (not in Custom Light preset):" -ForegroundColor Yellow
        $choices.InstallKDEConnect = Get-YesNoChoice -Title "Install KDE Connect?" -Description "Device connectivity and integration (share files, notifications, etc.)"
        
    } else {
        # Manual Selection Mode: Ask each question
        $choices.InstallKDEConnect = Get-YesNoChoice -Title "Install KDE Connect?" -Description "Device connectivity and integration (share files, notifications, etc.)"
        
        foreach ($software in $softwareList) {
            $key = "Install$($software.Name -replace '\s','')"
            $choices.$key = Get-YesNoChoice -Title "Install $($software.Name)?" -Description $software.Desc
        }
    }
    
    # Question: Copilot Instructions (Only if VS Code is selected or already installed)
    # Always ask, regardless of mode
    $vscodeInstalled = (Test-IsInstalled -WingetId "Microsoft.VisualStudioCode") -or (Get-Command "code" -ErrorAction SilentlyContinue)
    if ($choices.InstallVisualStudioCode -or $vscodeInstalled) {
        $msg = "Install VS Code Copilot Instructions?"
        if ($choices.InstallVisualStudioCode -and -not $vscodeInstalled) {
            $msg = "Install VS Code Copilot Instructions (will be applied after VS Code)?"
        }
        $choices.InstallCopilotInstructions = Get-YesNoChoice -Title $msg -Description "Adds custom rules/instructions for GitHub Copilot from LightZirconite/copilot-rules"
    }

    # Question: Mesh Agent (Always ask)
    $choices.InstallMeshAgent = Get-YesNoChoice -Title "Install Mesh Agent (Remote Management)?" -Description "Remote management and support agent"
    
    # Question: Defender Exclusion Folder (Always ask)
    $choices.SetupExclusionFolder = Get-YesNoChoice -Title "Create 'Excluded' folder in Documents?" -Description "Creates a folder excluded from Windows Defender scans (useful for tools/scripts)"

    # Additional Tool Selection (not in Custom Light preset)
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "Additional System Tools" -ForegroundColor White
    Write-Host "============================================" -ForegroundColor Yellow
    
    if ($useCustomLight) {
        # For Custom Light: Only ask for tools NOT in the preset
        $choices.InstallBulkCrapUninstaller = Get-YesNoChoice -Title "Install Bulk Crap Uninstaller?" -Description "Deep software uninstallation tool"
        $choices.InstallFilesApp = Get-YesNoChoice -Title "Install Files App?" -Description "Modern file manager"
        $choices.InstallLivelyWallpaper = Get-YesNoChoice -Title "Install Lively Wallpaper?" -Description "Animated wallpaper engine"
    } else {
        # Manual mode: ask each
        $choices.InstallBulkCrapUninstaller = Get-YesNoChoice -Title "Install Bulk Crap Uninstaller?" -Description "Deep software uninstallation tool"
        $choices.InstallRytunex = Get-YesNoChoice -Title "Install Rytunex?" -Description "System optimization tool"
        $choices.InstallTranslucentTB = Get-YesNoChoice -Title "Install TranslucentTB?" -Description "Taskbar transparency tool"
        $choices.InstallFilesApp = Get-YesNoChoice -Title "Install Files App?" -Description "Modern file manager"
        $choices.InstallNilesoftShell = Get-YesNoChoice -Title "Install Nilesoft Shell?" -Description "Context Menu customizer"
        $choices.InstallLivelyWallpaper = Get-YesNoChoice -Title "Install Lively Wallpaper?" -Description "Animated wallpaper engine"
        
        # Manual Mode: Ask for Gaming/Power/Nerd (since they are not pre-selected)
        $choices.InstallGamingStack = Get-YesNoChoice -Title "Install Gaming Stack?" -Description "Visual C++ Runtimes (AIO), DirectX, and Game Mode optimization"
        $choices.SetupPowerPlan = Get-YesNoChoice -Title "Enable Ultimate Performance Mode?" -Description "Optimizes Windows power settings for maximum speed"
        $choices.InstallNerdFonts = Get-YesNoChoice -Title "Install Nerd Fonts?" -Description "Required for icons in modern terminals (Oh My Posh, etc.)"
    }

    # Question: WSL
    $choices.InstallWSL = Get-YesNoChoice -Title "Install WSL (Linux Subsystem)?" -Description "Enables running Linux on Windows (Requires Restart)"

    # Windows 11 Specific: FluentFlyout
    # Check if Windows 11 (Build >= 22000)
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -eq 10 -and $osVersion.Build -ge 22000) {
        $choices.InstallFluentFlyout = Get-YesNoChoice -Title "Install FluentFlyout?" -Description "Modern audio/media flyout (Windows 11 style)"
    }

    # Windows 10 Specific: Theme Pack
    if ($osVersion.Major -eq 10 -and $osVersion.Build -lt 22000) {
        $choices.ApplyWindows11Theme = Get-YesNoChoice -Title "Apply Windows 11 Theme Pack?" -Description "Transforms Windows 10 appearance to look like Windows 11"
    }
    
    # Hardware-Specific Detection & Questions
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Magenta
    Write-Host "Hardware Detection & Drivers" -ForegroundColor White
    Write-Host "============================================" -ForegroundColor Magenta
    
    $hwInfo = Get-HardwareInfo
    $gpuInfo = Get-GPUInfo
    
    Write-Info "Detected: $($hwInfo.Manufacturer) $($hwInfo.Model)"
    if ($gpuInfo.GPUs.Count -gt 0) {
        Write-Info "GPU(s): $($gpuInfo.GPUs -join ', ')"
    }
    Write-Host ""
    
    # Steam Deck Detection
    if ($hwInfo.IsSteamDeck) {
        Write-Host "🎮 Steam Deck detected!" -ForegroundColor Cyan
        $choices.InstallSteamDeckTools = Get-YesNoChoice -Title "Install Steam Deck Tools?" -Description "For Steam Deck on Windows - provides drivers and fan control"
    }
    
    # Unowhy Detection
    if ($hwInfo.IsUnowhy) {
        Write-Host "💻 Unowhy device detected!" -ForegroundColor Cyan
        $choices.InstallUnowhyTools = Get-YesNoChoice -Title "Install Unowhy Tools?" -Description "Device-specific drivers for Unowhy computers"
    }
    
    # BIOS/Driver Updates
    Write-Host "🖥️ System: $($hwInfo.Manufacturer) $($hwInfo.Model)" -ForegroundColor Cyan
    $choices.InstallBiosUpdates = Get-YesNoChoice -Title "Check for BIOS & Driver Updates?" -Description "Uses official tools for Dell/Lenovo, or support page/Windows Update for others"
    
    # NVIDIA GPU Detection
    if ($gpuInfo.HasNVIDIA) {
        Write-Host "🎮 NVIDIA GPU detected!" -ForegroundColor Green
        $choices.InstallNVIDIADrivers = Get-YesNoChoice -Title "Install NVIDIA App & Drivers?" -Description "For NVIDIA GPUs - includes drivers and GeForce Experience replacement"
    }
    
    # AMD GPU Detection
    if ($gpuInfo.HasAMD) {
        Write-Host "🔴 AMD GPU detected!" -ForegroundColor Red
        $choices.InstallAMDDrivers = Get-YesNoChoice -Title "Install AMD Adrenalin & Drivers?" -Description "For AMD/Radeon GPUs - includes drivers and Adrenalin software"
    }
    
    # Intel GPU Detection
    if ($gpuInfo.HasIntel) {
        Write-Host "🔵 Intel GPU detected!" -ForegroundColor Blue
        $choices.InstallIntelTools = Get-YesNoChoice -Title "Install Intel GPU Tools?" -Description "Installs Driver & Support Assistant + Intel Graphics Software (Control Panel)"
    }
    
    Write-Host ""
    
    # Question: System Update
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

    # Win11Debloat
    if ($choices.DebloatMode -and $choices.DebloatMode -ne "None") {
        Invoke-Win11Debloat -Mode $choices.DebloatMode | Out-Null
    }

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
    foreach ($software in $softwareList) {
        $key = "Install$($software.Name -replace '\s','')"
        if ($choices.$key) {
            # Special handling for Spotify: use official installer + Spicetify
            if ($software.Name -eq "Spotify") {
                Install-Spotify | Out-Null
                Install-Spicetify
            } else {
                # Pass Fallback URL if it exists
                $fallback = if ($software.Fallback) { $software.Fallback } else { "" }
                # Pass Command check if it exists
                $cmdCheck = if ($software.Command) { $software.Command } else { "" }
                
                Install-WingetSoftware -PackageName $software.Name -WingetId $software.Id -FallbackUrl $fallback -CheckCommand $cmdCheck | Out-Null
            }
        }
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

    # Individual Tool Installations
    if ($choices.InstallBulkCrapUninstaller) {
        Install-BulkCrapUninstaller | Out-Null
    }
    
    if ($choices.InstallRytunex) {
        Install-Rytunex | Out-Null
    }
    
    if ($choices.InstallTranslucentTB) {
        Install-TranslucentTB | Out-Null
    }
    
    if ($choices.InstallFilesApp) {
        Install-FilesApp | Out-Null
    }
    
    if ($choices.InstallNilesoftShell) {
        Install-NilesoftShell | Out-Null
    }
    
    if ($choices.InstallFluentFlyout) {
        Install-FluentFlyout-GitHub | Out-Null
    }
    
    if ($choices.InstallLivelyWallpaper) {
        Install-LivelyWallpaper | Out-Null
    }
    
    if ($choices.ApplyWindows11Theme) {
        Apply-Windows11Theme | Out-Null
    }
    
    if ($choices.InstallSteamDeckTools) {
        Install-SteamDeckTools | Out-Null
    }
    
    if ($choices.InstallUnowhyTools) {
        Install-UnowhyTools | Out-Null
    }
    
    if ($choices.InstallBiosUpdates) {
        Install-BiosUpdates -HardwareInfo $hwInfo | Out-Null
    }

    if ($choices.InstallGamingStack) {
        Install-GamingStack | Out-Null
    }

    if ($choices.SetupPowerPlan) {
        Setup-PowerPlan | Out-Null
    }

    if ($choices.InstallWSL) {
        Install-WSL | Out-Null
    }

    if ($choices.InstallNerdFonts) {
        Install-NerdFonts | Out-Null
    }
    
    if ($choices.InstallNVIDIADrivers) {
        Install-NVIDIADrivers | Out-Null
    }
    
    if ($choices.InstallAMDDrivers) {
        Install-AMDDrivers | Out-Null
    }
    
    if ($choices.InstallIntelTools) {
        Install-IntelDrivers | Out-Null
        Install-IntelGraphicsSoftware | Out-Null
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
    
    # Show summary of specialized tools
    Show-InstalledToolsSummary -Choices $choices
    
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

# Show summary of installed tools
function Show-InstalledToolsSummary {
    param([hashtable]$Choices)
    
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           Installed Tools & Software Guide                     " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $toolsInstalled = @()
    
    if ($Choices.InstallBulkCrapUninstaller) {
        $toolsInstalled += @{Name="Bulk Crap Uninstaller"; Desc="Advanced software removal tool"; Source="GitHub: Klocman/Bulk-Crap-Uninstaller"}
    }
    
    if ($Choices.InstallRytunex) {
        $toolsInstalled += @{Name="Rytunex"; Desc="System optimization and tweaking tool"; Source="GitHub: rayenghanmi/RyTuneX"}
    }
    
    if ($Choices.InstallFilesApp) {
        $toolsInstalled += @{Name="Files App"; Desc="Modern file manager replacement"; Source="files.community"}
    }
    
    if ($Choices.InstallNilesoftShell) {
        $toolsInstalled += @{Name="Nilesoft Shell"; Desc="Advanced context menu customizer"; Source="GitHub: nilesoft/shell"}
    }
    
    if ($Choices.InstallFluentFlyout) {
        $toolsInstalled += @{Name="FluentFlyout"; Desc="Modern audio/media flyout"; Source="GitHub: unchihugo/FluentFlyout"}
    }
    
    # Device-specific tools
    if ($Choices.InstallSteamDeckTools) {
        $toolsInstalled += @{Name="Steam Deck Tools"; Desc="Drivers and fan control for Steam Deck hardware on Windows"; Source="GitHub: ayufan/steam-deck-tools"}
    }
    
    if ($Choices.InstallUnowhyTools) {
        $toolsInstalled += @{Name="Unowhy Tools"; Desc="Device-specific drivers for Unowhy computers"; Source="Unowhy official"}
    }
    
    if ($Choices.InstallKDEConnect) {
        $toolsInstalled += @{Name="KDE Connect"; Desc="Device integration - sync notifications, share files, and control your PC from your phone"; Source="KDE Project"}
    }
    
    # Display tools
    if ($toolsInstalled.Count -gt 0) {
        Write-Host "Specialized tools installed:" -ForegroundColor Yellow
        Write-Host ""
        
        foreach ($tool in $toolsInstalled) {
            Write-Host "  ● $($tool.Name)" -ForegroundColor White
            Write-Host "    $($tool.Desc)" -ForegroundColor Gray
            if ($tool.Source) {
                Write-Host "    Source: $($tool.Source)" -ForegroundColor DarkGray
            }
            if ($tool.Tips) {
                Write-Host "    ➤ Tip: $($tool.Tips)" -ForegroundColor Cyan
            }
            Write-Host ""
        }
    }
    
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
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
