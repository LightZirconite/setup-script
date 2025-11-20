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
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
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
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Info "Winget is already installed."
        return $true
    }

    Write-Info "Winget not found. Installing Winget and required frameworks..."
    
    $tempPath = [System.IO.Path]::GetTempPath()
    
    try {
        # 1. Install VCLibs (Framework)
        Write-Info "Downloading and installing VCLibs (Framework)..."
        $vcLibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
        $vcLibsPath = Join-Path $tempPath "Microsoft.VCLibs.x64.14.00.Desktop.appx"
        Invoke-WebRequest -Uri $vcLibsUrl -OutFile $vcLibsPath -UseBasicParsing
        Add-AppxPackage -Path $vcLibsPath
        
        # 2. Install UI Xaml (Framework)
        Write-Info "Downloading and installing UI Xaml (Framework)..."
        # Using a known stable version of UI Xaml 2.7
        $uiXamlUrl = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.7.3/Microsoft.UI.Xaml.2.7.x64.appx"
        $uiXamlPath = Join-Path $tempPath "Microsoft.UI.Xaml.2.7.x64.appx"
        Invoke-WebRequest -Uri $uiXamlUrl -OutFile $uiXamlPath -UseBasicParsing
        Add-AppxPackage -Path $uiXamlPath

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
        return $false
    }
}

# Install Office function
function Install-Office {
    Write-Info "Installing Microsoft Office..."
    
    try {
        $officeUrl = "https://c2rsetup.officeapps.live.com/c2r/download.aspx?ProductreleaseID=O365ProPlusRetail&platform=x64&language=en-us&version=O16GA"
        $tempPath = [System.IO.Path]::GetTempPath()
        $setupFile = Join-Path $tempPath "OfficeSetup.exe"
        
        Write-Info "Downloading Office setup..."
        Invoke-WebRequest -Uri $officeUrl -OutFile $setupFile -UseBasicParsing
        
        Write-Info "Executing Office setup..."
        Start-Process -FilePath $setupFile -Wait
        
        Remove-Item $setupFile -Force -ErrorAction SilentlyContinue
        Write-Success "Office installation completed"
        return $true
    } catch {
        Write-ErrorMsg "Failed to install Office: $($_.Exception.Message)"
        return $false
    }
}

# Activate Windows/Office
function Invoke-Activation {
    Write-Info "Opening Microsoft Activation Scripts (MAS)..."
    Write-Warning "A new PowerShell window will open. Please select your activation option there."
    
    try {
        Start-Process powershell -ArgumentList "-NoExit", "-WindowStyle", "Hidden", "-Command", "irm https://get.activated.win | iex" -Verb RunAs
        Write-Success "Activation window opened"
        return $true
    } catch {
        Write-ErrorMsg "Failed to open activation script: $($_.Exception.Message)"
        return $false
    }
}

# Check if software is installed via winget
function Test-IsInstalled {
    param([string]$WingetId)
    $process = Start-Process winget -ArgumentList "list --id $WingetId --exact --accept-source-agreements" -NoNewWindow -PassThru -Wait
    return ($process.ExitCode -eq 0)
}

# Install software via winget
function Install-WingetSoftware {
    param([string]$PackageName, [string]$WingetId)
    
    if (Test-IsInstalled -WingetId $WingetId) {
        Write-Info "$PackageName is already installed. Skipping..."
        return $true
    }

    Write-Info "Installing $PackageName via winget..."
    
    try {
        $process = Start-Process winget -ArgumentList "install --id $WingetId --accept-package-agreements --accept-source-agreements --silent" -NoNewWindow -PassThru -Wait
        
        if ($process.ExitCode -eq 0) {
            Write-Success "$PackageName installed successfully"
            return $true
        } elseif ($process.ExitCode -eq -2143309565) { # 0x803fb103
            Write-Warning "Skipping ${PackageName}: Not compatible with this Windows edition (LTSC/IoT) without full Store support."
            return $false
        } else {
            Write-ErrorMsg "Failed to install ${PackageName}. Exit code: $($process.ExitCode)"
            return $false
        }
    } catch {
        Write-ErrorMsg "Failed to execute winget for ${PackageName}: $($_.Exception.Message)"
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
    
    # Check if already installed via file path (common location)
    $rytunexPath = "$env:ProgramFiles\RyTuneX\RyTuneX.exe"
    if (Test-Path $rytunexPath) {
        Write-Info "Rytunex detected at $rytunexPath. Skipping..."
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
    
    # Fallback to direct download if winget fails
    Write-Info "Winget installation failed or package not found. Attempting direct download from GitHub..."
    try {
        $apiUrl = "https://api.github.com/repos/rayenghanmi/RyTuneX/releases/latest"
        Write-Info "Fetching latest release info from GitHub..."
        $release = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
        
        # Look for the specific setup file
        $setupAsset = $release.assets | Where-Object { $_.name -eq "RyTuneXSetup.exe" } | Select-Object -First 1
        
        if ($setupAsset) {
            $tempPath = [System.IO.Path]::GetTempPath()
            $setupFile = Join-Path $tempPath $setupAsset.name
            
            Write-Info "Downloading Rytunex $($release.tag_name)..."
            Invoke-WebRequest -Uri $setupAsset.browser_download_url -OutFile $setupFile -UseBasicParsing
            
            Write-Info "Installing Rytunex..."
            Start-Process -FilePath $setupFile -ArgumentList "/VERYSILENT" -Wait
            
            Remove-Item $setupFile -Force -ErrorAction SilentlyContinue
            Write-Success "Rytunex installed successfully via direct download"
            return $true
        } else {
            Write-ErrorMsg "Could not find 'RyTuneXSetup.exe' in the latest release assets."
            return $false
        }
    } catch {
        Write-ErrorMsg "Failed to install Rytunex via direct download: $($_.Exception.Message)"
        return $false
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
    Install-WingetSoftware -PackageName "Files App" -WingetId "9NGHP3DX8HDX"
    
    Write-Success "Store apps installation initiated"
}

# Pin Files App to taskbar
function Set-FilesAppPinned {
    Write-Info "Please pin Files App to your taskbar manually after installation completes."
    Write-Host "Location: Start Menu > Files > Right-click > Pin to taskbar" -ForegroundColor Yellow
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
            # Redirect output to null to hide potential ClipRenew errors which are harmless here
            Start-Process -FilePath $wsresetPath -ArgumentList "-i" -NoNewWindow -Wait -RedirectStandardOutput $null -RedirectStandardError $null
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

# Main Script Execution
function Start-Setup {
    # Detect Windows Edition silently first
    $osData = Get-WindowsEdition
    $windowsEdition = $osData.Type
    
    Show-Banner
    
    # Ensure Winget and Frameworks are installed immediately
    Install-Winget

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
    
    # Question 4-13: Software installations via winget
    $softwareList = @(
        @{Name="Discord"; Id="Discord.Discord"; Desc="Voice, video, and text communication platform"},
        @{Name="Steam"; Id="Valve.Steam"; Desc="Gaming platform and store"},
        @{Name="Spotify"; Id="Spotify.Spotify"; Desc="Music streaming service"},
        @{Name="Terminus"; Id="Eugeny.Terminus"; Desc="Modern terminal emulator"},
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
    
    # Question 14: Mesh Agent
    $choices.InstallMeshAgent = Get-YesNoChoice -Title "Install Mesh Agent (Remote Management)?" -Description "Remote management and support agent"
    
    # Question 15: Setup Mode
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Yellow
    Write-Host "Choose PC Setup Mode:" -ForegroundColor White
    Write-Host "1. Performance mode only" -ForegroundColor White
    Write-Host "   - Bulk Crap Uninstaller (deep software removal)" -ForegroundColor Gray
    Write-Host "   - Rytunex (system optimization)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. Performance + Enhanced Style mode" -ForegroundColor White
    Write-Host "   - All performance tools" -ForegroundColor Gray
    Write-Host "   - WinPaletter (Windows theming)" -ForegroundColor Gray
    Write-Host "   - TranslucentTB (taskbar transparency)" -ForegroundColor Gray
    Write-Host "   - Files App (modern file manager)" -ForegroundColor Gray
    Write-Host "   - Optional: Lively Wallpaper" -ForegroundColor Gray
    Write-Host "============================================" -ForegroundColor Yellow
    
    do {
        $setupMode = Read-Host "Enter choice (1-2)"
    } while ($setupMode -notin @("1", "2"))
    
    $choices.SetupMode = $setupMode
    
    if ($setupMode -eq "2") {
        $choices.InstallLivelyWallpaper = Get-YesNoChoice -Title "Install Lively Wallpaper?" -Description "Animated wallpaper engine (alternative to Wallpaper Engine)"
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
        
        # Check if Store is already installed
        $isStoreInstalled = Get-AppxPackage -Name Microsoft.WindowsStore
        
        if ($isStoreInstalled) {
            Write-Info "Microsoft Store is detected on your system."
            $choices.EnableMicrosoftStore = Get-YesNoChoice -Title "Repair/Update Microsoft Store components?" -Description "Recommended if you have trouble installing Store apps (fixes missing frameworks)"
        } else {
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
    Start-Process winget -ArgumentList "source update" -NoNewWindow -Wait
    
    # Execute installations based on choices
    if ($choices.InstallOffice) {
        Install-Office
    }
    
    if ($choices.Activate) {
        Invoke-Activation
        Write-Warning "Please complete activation in the new window, then return here."
        Read-Host "Press Enter when activation is complete to continue"
    }
    
    if ($choices.InstallKDEConnect) {
        Install-KDEConnect
    }
    
    # Install software via winget
    foreach ($software in $softwareList) {
        $key = "Install$($software.Name -replace '\s','')"
        if ($choices.$key) {
            Install-WingetSoftware -PackageName $software.Name -WingetId $software.Id
        }
    }
    
    if ($choices.InstallMeshAgent) {
        Install-MeshAgent
    }
    
    # Setup Mode installations
    if ($choices.SetupMode -eq "1" -or $choices.SetupMode -eq "2") {
        Write-Info "Installing Performance Mode tools..."
        Install-BulkCrapUninstaller
        Install-Rytunex
        
        Write-Info "Recommendation: For maximum performance, consider installing Windows 10 IoT Enterprise LTSC 2021"
        Write-Info "Download: https://delivery.activated.win/dbmassgrave/en-us_windows_10_iot_enterprise_ltsc_2021_x64_dvd_257ad90f.iso"
    }
    
    if ($choices.SetupMode -eq "2") {
        Write-Info "Installing Enhanced Style Mode tools..."
        Install-WinPaletter
        Install-StoreApps
        Set-FilesAppPinned
        
        if ($choices.InstallLivelyWallpaper) {
            Install-LivelyWallpaper
        }
    }
    
    if ($choices.InstallSteamDeckTools) {
        Install-SteamDeckTools
    }
    
    if ($choices.InstallUnowhyTools) {
        Install-UnowhyTools
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
            winget source update --name msstore

            if ($choices.InstallNotepad) {
                # Try installing via ID first, then fallback to name if needed
                # Using --accept-source-agreements to bypass prompts
                Install-WingetSoftware -PackageName "Notepad" -WingetId "9MSMLRH6LZF3"
            }
            
            if ($choices.InstallWindowsTerminal) {
                Install-WingetSoftware -PackageName "Windows Terminal" -WingetId "Microsoft.WindowsTerminal"
            }
            
            if ($choices.InstallCalculator) {
                Install-WingetSoftware -PackageName "Calculator" -WingetId "9WZDNCRFHVN5"
            }
            
            if ($choices.InstallCamera) {
                Install-WingetSoftware -PackageName "Camera" -WingetId "9WZDNCRFJBBG"
            }
            
            if ($choices.InstallMediaPlayer) {
                Install-WingetSoftware -PackageName "Media Player" -WingetId "9WZDNCRFJ3PT"
            }
            
            if ($choices.InstallPhotos) {
                Install-WingetSoftware -PackageName "Photos" -WingetId "9WZDNCRFJBH4"
            }
        } else {
            Write-Warning "Microsoft Store is not detected. Skipping Store apps installation to prevent errors."
        }
    }
    
    # System Update (done last)
    if ($choices.UpdateAllSoftware) {
        Update-AllSoftware
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
