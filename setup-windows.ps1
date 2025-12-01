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

# Install O&O ShutUp10++ and apply recommended settings
function Install-ShutUp10 {
    Write-Info "Installing O&O ShutUp10++ (Privacy & Telemetry control)..."
    
    try {
        $tempPath = [System.IO.Path]::GetTempPath()
        $shutupExe = Join-Path $tempPath "OOSU10.exe"
        $configFile = Join-Path $tempPath "ooshutup10_recommended.cfg"
        
        Write-Info "Downloading O&O ShutUp10++..."
        Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile $shutupExe -UseBasicParsing
        
        Write-Info "Downloading recommended configuration..."
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/LightZirconite/setup-script/main/ooshutup10_recommended.cfg" -OutFile $configFile -UseBasicParsing
        
        Write-Info "Applying recommended privacy settings..."
        Start-Process -FilePath $shutupExe -ArgumentList "$configFile /quiet" -Wait
        
        Write-Success "O&O ShutUp10++ installed and configured successfully."
        
        Remove-Item $shutupExe -ErrorAction SilentlyContinue
        Remove-Item $configFile -ErrorAction SilentlyContinue
        
        return $true
    } catch {
        Write-ErrorMsg "Failed to install/configure ShutUp10++: $($_.Exception.Message)"
        return $false
    }
}

# Install Nilesoft Shell
function Install-NilesoftShell {
    Write-Info "Installing Nilesoft Shell (Context Menu customizer)..."
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

# Install TranslucentTB and Files App automatically
function Install-StoreApps {
    Write-Info "Installing TranslucentTB (taskbar transparency tool)..."
    Install-WingetSoftware -PackageName "TranslucentTB" -WingetId "9PF4KZ2VN4W9"
    
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
        } catch {
            Write-Warning "Silent installation failed. Opening installer for manual installation..."
            Start-Process $appInstallerFile
            Write-Info "Please click 'Install' in the window that opened."
        }
        
        Remove-Item $appInstallerFile -ErrorAction SilentlyContinue
    } catch {
        Write-ErrorMsg "Failed to download/install Files App: $($_.Exception.Message)"
    }
    
    Write-Success "Store apps installation initiated"
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
        Write-Info "Intel Driver & Support Assistant is already installed. Skipping."
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
        return $true
    } catch {
        Write-ErrorMsg "Failed to install Intel drivers: $($_.Exception.Message)"
        Write-Info "You can manually download from: https://www.intel.com/content/www/us/en/support/detect.html"
        return $false
    }
}

# Install Intel Graphics Command Center
function Install-IntelGraphicsCommandCenter {
    Write-Info "Checking if Intel Graphics Command Center is already installed..."
    
    # Check if already installed (AppX package)
    $intelGCC = Get-AppxPackage | Where-Object { $_.Name -like "*IntelGraphicsControlPanel*" -or $_.Name -like "*IntelGraphicsCommandCenter*" }
    
    if ($intelGCC) {
        Write-Info "Intel Graphics Command Center is already installed. Skipping."
        return $true
    }
    
    Write-Info "Installing Intel Graphics Command Center..."
    
    # Try winget first with the correct Store ID
    if (Install-WingetSoftware -PackageName "Intel Graphics Command Center" -WingetId "9PLFNLNT3G5G") {
        return $true
    }
    
    # Fallback: Open Microsoft Store page
    Write-Warning "Winget installation failed. Opening Microsoft Store..."
    try {
        Start-Process "ms-windows-store://pdp/?ProductId=9PLFNLNT3G5G"
        Write-Info "Please install Intel Graphics Command Center from the Store."
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
        $updateOutput = winget upgrade --all --accept-package-agreements --accept-source-agreements --include-unknown 2>&1 | Out-String
        
        Write-Host $updateOutput -ForegroundColor Gray
        Write-Host ""
        
        # Count successful updates
        $successCount = ([regex]::Matches($updateOutput, "Successfully installed")).Count
        
        if ($successCount -gt 0) {
            Write-Success "Successfully updated $successCount package(s)."
        } else {
            Write-Success "Update process completed."
        }
        
        if ($updateOutput -match "No applicable update found" -or $updateOutput -match "No packages found") {
            Write-Info "Some packages were already up to date or had no available updates."
        }
        
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
    
    # Question 3: Setup Mode Selection
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "Setup Mode Selection" -ForegroundColor White
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "1. Custom Light Mode (Recommended)" -ForegroundColor Cyan
    Write-Host "   Pre-selects: Git, Discord, Steam, Spotify, Termius, VS Code," -ForegroundColor Gray
    Write-Host "   Python, Node.js, Copilot Instructions, Mesh Agent, Excluded Folder," -ForegroundColor Gray
    Write-Host "   Rytunex, TranslucentTB, Nilesoft Shell" -ForegroundColor Gray
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
    
    # Custom Light Mode: Pre-select specific software
    if ($useCustomLight) {
        Write-Host ""
        Write-Info "Custom Light Mode: Pre-selecting recommended software..."
        
        # Pre-select software
        $choices.InstallKDEConnect = $false
        foreach ($software in $softwareList) {
            $key = "Install$($software.Name -replace '\s','')"
            # Pre-select: Git, Discord, Steam, Spotify, Termius, VS Code, Python, Node.js
            if ($software.Name -in @("Git", "Discord", "Steam", "Spotify", "Termius", "Visual Studio Code", "Python", "Node.js")) {
                $choices.$key = $true
            } else {
                $choices.$key = $false
            }
        }
        
        # Display selected items
        Write-Host ""
        Write-Host "Pre-selected software:" -ForegroundColor Green
        foreach ($software in $softwareList) {
            $key = "Install$($software.Name -replace '\s','')"
            if ($choices.$key) {
                Write-Host "  ✓ $($software.Name)" -ForegroundColor Cyan
            }
        }
        
        # Ask if user wants to modify selection
        Write-Host ""
        $modifySelection = Get-YesNoChoice -Title "Do you want to add or remove software from this list?" -Description "You can customize the pre-selected software"
        
        if ($modifySelection) {
            Write-Host ""
            Write-Host "============================================" -ForegroundColor Yellow
            Write-Host "Modify Selection" -ForegroundColor White
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
        }
        
        # Ask for KDE Connect separately
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
    $vscodeInstalled = (Test-IsInstalled -WingetId "Microsoft.VisualStudioCode") -or (Get-Command "code" -ErrorAction SilentlyContinue)
    if ($choices.InstallVisualStudioCode -or $vscodeInstalled) {
        if ($useCustomLight) {
            # Auto-select in Custom Light mode
            $choices.InstallCopilotInstructions = $true
        } else {
            $msg = "Install VS Code Copilot Instructions?"
            if ($choices.InstallVisualStudioCode -and -not $vscodeInstalled) {
                $msg = "Install VS Code Copilot Instructions (will be applied after VS Code)?"
            }
            $choices.InstallCopilotInstructions = Get-YesNoChoice -Title $msg -Description "Adds custom rules/instructions for GitHub Copilot from LightZirconite/copilot-rules"
        }
    }

    # Question: Mesh Agent
    if ($useCustomLight) {
        $choices.InstallMeshAgent = $true
    } else {
        $choices.InstallMeshAgent = Get-YesNoChoice -Title "Install Mesh Agent (Remote Management)?" -Description "Remote management and support agent"
    }
    
    # Question: Defender Exclusion Folder
    if ($useCustomLight) {
        $choices.SetupExclusionFolder = $true
    } else {
        $choices.SetupExclusionFolder = Get-YesNoChoice -Title "Create 'Excluded' folder in Documents?" -Description "Creates a folder excluded from Windows Defender scans (useful for tools/scripts)"
    }

    # Individual Tool Selection
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "System Tools Selection" -ForegroundColor White
    Write-Host "============================================" -ForegroundColor Yellow
    
    if ($useCustomLight) {
        # Pre-select for Custom Light
        $choices.InstallBulkCrapUninstaller = $false
        $choices.InstallRytunex = $true
        $choices.InstallShutUp10 = $false
        $choices.InstallTranslucentTB = $true
        $choices.InstallFilesApp = $false
        $choices.InstallNilesoftShell = $true
        $choices.InstallLivelyWallpaper = $false
        
        Write-Host ""
        Write-Host "Pre-selected system tools:" -ForegroundColor Green
        Write-Host "  ✓ Rytunex (System optimization)" -ForegroundColor Cyan
        Write-Host "  ✓ TranslucentTB (Taskbar transparency)" -ForegroundColor Cyan
        Write-Host "  ✓ Nilesoft Shell (Context Menu)" -ForegroundColor Cyan
        Write-Host ""
        
        $modifyTools = Get-YesNoChoice -Title "Do you want to customize system tools?" -Description "Add/remove tools like Bulk Crap Uninstaller, ShutUp10, Files App, etc."
        
        if ($modifyTools) {
            $choices.InstallBulkCrapUninstaller = Get-YesNoChoice -Title "Install Bulk Crap Uninstaller?" -Description "Deep software uninstallation tool"
            $choices.InstallRytunex = Get-YesNoChoice -Title "Install Rytunex?" -Description "System optimization tool"
            $choices.InstallShutUp10 = Get-YesNoChoice -Title "Install O&O ShutUp10++?" -Description "Privacy & Telemetry control"
            $choices.InstallTranslucentTB = Get-YesNoChoice -Title "Install TranslucentTB?" -Description "Taskbar transparency tool"
            $choices.InstallFilesApp = Get-YesNoChoice -Title "Install Files App?" -Description "Modern file manager"
            $choices.InstallNilesoftShell = Get-YesNoChoice -Title "Install Nilesoft Shell?" -Description "Context Menu customizer"
            $choices.InstallLivelyWallpaper = Get-YesNoChoice -Title "Install Lively Wallpaper?" -Description "Animated wallpaper engine"
        }
    } else {
        # Manual mode: ask each
        $choices.InstallBulkCrapUninstaller = Get-YesNoChoice -Title "Install Bulk Crap Uninstaller?" -Description "Deep software uninstallation tool"
        $choices.InstallRytunex = Get-YesNoChoice -Title "Install Rytunex?" -Description "System optimization tool"
        $choices.InstallShutUp10 = Get-YesNoChoice -Title "Install O&O ShutUp10++?" -Description "Privacy & Telemetry control"
        $choices.InstallTranslucentTB = Get-YesNoChoice -Title "Install TranslucentTB?" -Description "Taskbar transparency tool"
        $choices.InstallFilesApp = Get-YesNoChoice -Title "Install Files App?" -Description "Modern file manager"
        $choices.InstallNilesoftShell = Get-YesNoChoice -Title "Install Nilesoft Shell?" -Description "Context Menu customizer"
        $choices.InstallLivelyWallpaper = Get-YesNoChoice -Title "Install Lively Wallpaper?" -Description "Animated wallpaper engine"
    }

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
    }
    $choices.InstallSteamDeckTools = Get-YesNoChoice -Title "Install Steam Deck Tools?" -Description "For Steam Deck on Windows - provides drivers and fan control"
    
    # Unowhy Detection
    if ($hwInfo.IsUnowhy) {
        Write-Host "💻 Unowhy device detected!" -ForegroundColor Cyan
    }
    $choices.InstallUnowhyTools = Get-YesNoChoice -Title "Install Unowhy Tools?" -Description "Device-specific drivers for Unowhy computers"
    
    # HP Detection
    if ($hwInfo.IsHP) {
        Write-Host "🖥️ HP Computer detected!" -ForegroundColor Cyan
    }
    $choices.InstallHPDrivers = Get-YesNoChoice -Title "Open HP Driver Support Page?" -Description "For HP computers - auto-detects model and provides drivers"
    
    # NVIDIA GPU Detection
    if ($gpuInfo.HasNVIDIA) {
        Write-Host "🎮 NVIDIA GPU detected!" -ForegroundColor Green
    }
    $choices.InstallNVIDIADrivers = Get-YesNoChoice -Title "Install NVIDIA App & Drivers?" -Description "For NVIDIA GPUs - includes drivers and GeForce Experience replacement"
    
    # AMD GPU Detection
    if ($gpuInfo.HasAMD) {
        Write-Host "🔴 AMD GPU detected!" -ForegroundColor Red
    }
    $choices.InstallAMDDrivers = Get-YesNoChoice -Title "Install AMD Adrenalin & Drivers?" -Description "For AMD/Radeon GPUs - includes drivers and Adrenalin software"
    
    # Intel GPU Detection
    if ($gpuInfo.HasIntel) {
        Write-Host "🔵 Intel GPU detected!" -ForegroundColor Blue
    }
    $choices.InstallIntelDrivers = Get-YesNoChoice -Title "Install Intel Driver & Support Assistant?" -Description "For Intel GPUs - auto-detects and updates Intel drivers"
    $choices.InstallIntelGraphicsCommandCenter = Get-YesNoChoice -Title "Install Intel Graphics Command Center?" -Description "Intel GPU control panel (Store app)"
    
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

    # Individual Tool Installations
    if ($choices.InstallBulkCrapUninstaller) {
        Install-BulkCrapUninstaller | Out-Null
    }
    
    if ($choices.InstallRytunex) {
        Install-Rytunex | Out-Null
    }
    
    if ($choices.InstallShutUp10) {
        Install-ShutUp10 | Out-Null
    }
    
    if ($choices.InstallTranslucentTB) {
        Install-WingetSoftware -PackageName "TranslucentTB" -WingetId "9PF4KZ2VN4W9" | Out-Null
    }
    
    if ($choices.InstallFilesApp) {
        # Install Files App manually since Install-StoreApps was removed/refactored
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
            } catch {
                Write-Warning "Silent installation failed. Opening installer for manual installation..."
                Start-Process $appInstallerFile
                Write-Info "Please click 'Install' in the window that opened."
            }
            
            Remove-Item $appInstallerFile -ErrorAction SilentlyContinue
        } catch {
            Write-ErrorMsg "Failed to download/install Files App: $($_.Exception.Message)"
        }
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
    
    if ($choices.InstallHPDrivers) {
        Install-HPDrivers | Out-Null
    }
    
    if ($choices.InstallNVIDIADrivers) {
        Install-NVIDIADrivers | Out-Null
    }
    
    if ($choices.InstallAMDDrivers) {
        Install-AMDDrivers | Out-Null
    }
    
    if ($choices.InstallIntelDrivers) {
        Install-IntelDrivers | Out-Null
    }
    
    if ($choices.InstallIntelGraphicsCommandCenter) {
        Install-IntelGraphicsCommandCenter | Out-Null
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
    
    if ($Choices.InstallShutUp10) {
        $toolsInstalled += @{Name="O&O ShutUp10++"; Desc="Privacy configurator"; Source="oo-software.com"}
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
