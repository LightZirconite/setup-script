#Requires -RunAsAdministrator

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

# Color output functions
function Write-Info { param($Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param($Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warning { param($Message) Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-ErrorMsg { param($Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

# Banner
function Show-Banner {
    Write-Host @"
╔═══════════════════════════════════════════════════════════╗
║          Windows Setup & Configuration Script            ║
║                     Version 1.0.0                         ║
╚═══════════════════════════════════════════════════════════╝
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
        
        Write-Info "Detected Windows Edition: $editionId"
        Write-Info "OS: $($osInfo.OsName)"
        
        if ($editionId -like "*LTSC*" -or $editionId -like "*IoT*" -or $editionId -like "*Enterprise*LTSC*") {
            Write-Warning "LTSC/IoT Edition detected - additional setup options will be available"
            return "LTSC"
        } else {
            Write-Info "Standard Windows 10/11 Edition detected"
            return "Standard"
        }
    } catch {
        Write-ErrorMsg "Failed to detect Windows edition: $_"
        return "Unknown"
    }
}

# Yes/No prompt function with description
function Get-YesNoChoice {
    param(
        [string]$Title,
        [string]$Description = ""
    )
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host $Title -ForegroundColor White
    if ($Description) {
        Write-Host $Description -ForegroundColor Gray
    }
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Yellow
    
    do {
        $choice = Read-Host "Your choice (Y/N)"
        $choice = $choice.ToUpper()
    } while ($choice -ne "Y" -and $choice -ne "N")
    
    return $choice -eq "Y"
}

# Install Office function
function Install-Office {
    param([string]$Method)
    
    Write-Info "Installing Microsoft Office..."
    
    if ($Method -eq "winget") {
        try {
            winget install Microsoft.Office --accept-package-agreements --accept-source-agreements
            Write-Success "Office installed via winget"
            return $true
        } catch {
            Write-ErrorMsg "Failed to install Office via winget: $_"
            return $false
        }
    } else {
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
            Write-ErrorMsg "Failed to install Office via direct download: $_"
            return $false
        }
    }
}

# Activate Windows/Office
function Invoke-Activation {
    param([string]$Target)
    
    Write-Info "Opening activation script for: $Target"
    Write-Warning "A new PowerShell window will open. Follow the instructions there."
    
    try {
        Start-Process powershell -ArgumentList "-NoExit", "-Command", "irm https://get.activated.win | iex" -Verb RunAs
        Write-Success "Activation window opened"
        return $true
    } catch {
        Write-ErrorMsg "Failed to open activation script: $_"
        return $false
    }
}

# Install software via winget
function Install-WingetSoftware {
    param([string]$PackageName, [string]$WingetId)
    
    Write-Info "Installing $PackageName via winget..."
    
    try {
        winget install $WingetId --accept-package-agreements --accept-source-agreements
        Write-Success "$PackageName installed successfully"
        return $true
    } catch {
        Write-ErrorMsg "Failed to install $PackageName: $_"
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
        Write-ErrorMsg "Failed to install Mesh Agent: $_"
        return $false
    }
}

# Install Bulk Crap Uninstaller
function Install-BulkCrapUninstaller {
    Write-Info "Installing Bulk Crap Uninstaller (deep software uninstallation tool)..."
    
    try {
        $apiUrl = "https://api.github.com/repos/Klocman/Bulk-Crap-Uninstaller/releases/latest"
        $release = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
        $setupAsset = $release.assets | Where-Object { $_.name -like "*setup.exe" } | Select-Object -First 1
        
        if ($setupAsset) {
            $tempPath = [System.IO.Path]::GetTempPath()
            $setupFile = Join-Path $tempPath $setupAsset.name
            
            Write-Info "Downloading BCUninstaller $($release.tag_name)..."
            Invoke-WebRequest -Uri $setupAsset.browser_download_url -OutFile $setupFile -UseBasicParsing
            
            Write-Info "Installing BCUninstaller..."
            Start-Process -FilePath $setupFile -ArgumentList "/VERYSILENT" -Wait
            
            Remove-Item $setupFile -Force -ErrorAction SilentlyContinue
            Write-Success "Bulk Crap Uninstaller installed successfully"
            return $true
        } else {
            Write-ErrorMsg "Could not find setup file in latest release"
            return $false
        }
    } catch {
        Write-ErrorMsg "Failed to install Bulk Crap Uninstaller: $_"
        return $false
    }
}

# Install Rytunex
function Install-Rytunex {
    Write-Info "Installing Rytunex (system optimization tool)..."
    Install-WingetSoftware -PackageName "Rytunex" -WingetId "rytunex"
}

# Install WinPaletter
function Install-WinPaletter {
    Write-Info "Installing WinPaletter (Windows theming tool)..."
    
    try {
        winget install Abdelrhman-AK.WinPaletter --accept-package-agreements --accept-source-agreements
        Write-Success "WinPaletter installed successfully"
        return $true
    } catch {
        Write-ErrorMsg "Failed to install WinPaletter: $_"
        return $false
    }
}

# Install Lively Wallpaper
function Install-LivelyWallpaper {
    Write-Info "Installing Lively Wallpaper..."
    
    try {
        $apiUrl = "https://api.github.com/repos/rocksdanister/lively/releases/latest"
        $release = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
        $setupAsset = $release.assets | Where-Object { $_.name -like "*setup*.exe" -and $_.name -like "*full*" } | Select-Object -First 1
        
        if ($setupAsset) {
            $tempPath = [System.IO.Path]::GetTempPath()
            $setupFile = Join-Path $tempPath $setupAsset.name
            
            Write-Info "Downloading Lively Wallpaper $($release.tag_name)..."
            Invoke-WebRequest -Uri $setupAsset.browser_download_url -OutFile $setupFile -UseBasicParsing
            
            Write-Info "Installing Lively Wallpaper..."
            Start-Process -FilePath $setupFile -ArgumentList "/VERYSILENT" -Wait
            
            Remove-Item $setupFile -Force -ErrorAction SilentlyContinue
            Write-Success "Lively Wallpaper installed successfully"
            return $true
        } else {
            Write-ErrorMsg "Could not find setup file in latest release"
            return $false
        }
    } catch {
        Write-ErrorMsg "Failed to install Lively Wallpaper: $_"
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
        Write-ErrorMsg "Failed to open store for $AppName: $_"
        return $false
    }
}

# Install TranslucentTB and Files App automatically
function Install-StoreApps {
    Write-Info "Installing TranslucentTB (taskbar transparency tool)..."
    winget install 9PF4KZ2VN4W9 --accept-package-agreements --accept-source-agreements
    
    Write-Info "Installing Files App (modern file manager)..."
    winget install 9NGHP3DX8HDX --accept-package-agreements --accept-source-agreements
    
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
    
    try {
        $apiUrl = "https://api.github.com/repos/ayufan/steam-deck-tools/releases/latest"
        $release = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
        $setupAsset = $release.assets | Where-Object { $_.name -like "*setup.exe" } | Select-Object -First 1
        
        if ($setupAsset) {
            $tempPath = [System.IO.Path]::GetTempPath()
            $setupFile = Join-Path $tempPath $setupAsset.name
            
            Write-Info "Downloading Steam Deck Tools $($release.tag_name)..."
            Invoke-WebRequest -Uri $setupAsset.browser_download_url -OutFile $setupFile -UseBasicParsing
            
            Write-Info "Installing Steam Deck Tools..."
            Start-Process -FilePath $setupFile -Wait
            
            Remove-Item $setupFile -Force -ErrorAction SilentlyContinue
            Write-Success "Steam Deck Tools installed successfully"
            return $true
        } else {
            Write-ErrorMsg "Could not find setup file in latest release"
            return $false
        }
    } catch {
        Write-ErrorMsg "Failed to install Steam Deck Tools: $_"
        return $false
    }
}

# Install Unowhy Tools
function Install-UnowhyTools {
    Write-Info "Installing Unowhy Tools (device-specific drivers)..."
    Install-WingetSoftware -PackageName "Unowhy Tools" -WingetId "Unowhy Tools"
}

# Install KDE Connect
function Install-KDEConnect {
    Write-Info "Installing KDE Connect (device connectivity and integration)..."
    
    try {
        $baseUrl = "https://mirrors.ircam.fr/pub/KDE/Attic/release-service/"
        
        Write-Info "Fetching latest KDE Connect release..."
        $response = Invoke-WebRequest -Uri $baseUrl -UseBasicParsing
        $versions = $response.Links | Where-Object { $_.href -match '^\d+\.\d+' } | 
                    ForEach-Object { $_.href.TrimEnd('/') } | 
                    Sort-Object -Descending | Select-Object -First 1
        
        if ($versions) {
            $versionUrl = "$baseUrl$versions/windows/"
            $versionPage = Invoke-WebRequest -Uri $versionUrl -UseBasicParsing
            $kdeConnectFile = $versionPage.Links | Where-Object { $_.href -like "*kdeconnect-kde*windows*.exe" } | 
                             Select-Object -First 1
            
            if ($kdeConnectFile) {
                $downloadUrl = $versionUrl + $kdeConnectFile.href
                $tempPath = [System.IO.Path]::GetTempPath()
                $setupFile = Join-Path $tempPath $kdeConnectFile.href
                
                Write-Info "Downloading KDE Connect..."
                Invoke-WebRequest -Uri $downloadUrl -OutFile $setupFile -UseBasicParsing
                
                Write-Info "Installing KDE Connect..."
                Start-Process -FilePath $setupFile -Wait
                
                Remove-Item $setupFile -Force -ErrorAction SilentlyContinue
                Write-Success "KDE Connect installed successfully"
                return $true
            }
        }
        
        Write-ErrorMsg "Could not find KDE Connect download"
        return $false
    } catch {
        Write-ErrorMsg "Failed to install KDE Connect: $_"
        return $false
    }
}

# Update all software
function Update-AllSoftware {
    Write-Info "Updating all installed software via winget..."
    
    try {
        winget upgrade --all --accept-package-agreements --accept-source-agreements
        Write-Success "Software updates completed"
        return $true
    } catch {
        Write-ErrorMsg "Failed to update software: $_"
        return $false
    }
}

# Enable Microsoft Store on LTSC
function Enable-MicrosoftStore {
    Write-Info "Enabling Microsoft Store on LTSC..."
    
    try {
        $script = @"
`$progressPreference = 'silentlyContinue'
Write-Information "Downloading LTSC Add Store..."
Invoke-WebRequest -Uri https://github.com/kkkgo/LTSC-Add-MicrosoftStore/releases/latest/download/Add-Store.cmd -OutFile `$env:TEMP\Add-Store.cmd
Write-Information "Installing Microsoft Store..."
Start-Process -FilePath `$env:TEMP\Add-Store.cmd -Wait
"@
        Invoke-Expression $script
        Write-Success "Microsoft Store enabled. Please restart your computer."
        return $true
    } catch {
        Write-ErrorMsg "Failed to enable Microsoft Store: $_"
        return $false
    }
}

# Main Script Execution
function Start-Setup {
    Show-Banner
    
    if (-not (Test-IsAdmin)) {
        Write-ErrorMsg "This script must be run as Administrator!"
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    # Detect Windows Edition
    Write-Info "Step 1: Detecting Windows Edition..."
    $windowsEdition = Get-WindowsEdition
    Start-Sleep -Seconds 2
    
    # Store all user choices
    $choices = @{}
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  CONFIGURATION PHASE - Please answer all questions first  " -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    
    # Question 1: Install Office
    $choices.InstallOffice = Get-YesNoChoice -Title "Install Microsoft Office?" -Description "Microsoft Office suite (Word, Excel, PowerPoint, etc.)"
    if ($choices.InstallOffice) {
        $choices.OfficeMethod = Get-YesNoChoice -Title "Use winget for Office installation?" -Description "Y = winget (faster), N = Direct download from Microsoft"
        $choices.OfficeMethod = if ($choices.OfficeMethod) { "winget" } else { "direct" }
    }
    
    # Question 2: Activate Windows/Office
    $choices.Activate = Get-YesNoChoice -Title "Activate Windows/Office?" -Description "Opens Microsoft Activation Scripts (MAS) for activation"
    if ($choices.Activate) {
        Write-Host ""
        Write-Host "What would you like to activate?" -ForegroundColor Yellow
        Write-Host "1. Windows only" -ForegroundColor White
        Write-Host "2. Office only" -ForegroundColor White
        Write-Host "3. Both Windows and Office" -ForegroundColor White
        do {
            $activateChoice = Read-Host "Enter choice (1-3)"
        } while ($activateChoice -notin @("1", "2", "3"))
        
        $choices.ActivateTarget = switch ($activateChoice) {
            "1" { "Windows" }
            "2" { "Office" }
            "3" { "Both" }
        }
    }
    
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
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Yellow
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
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Yellow
    
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
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host "     LTSC/IoT Edition Detected - Additional Options        " -ForegroundColor Magenta
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host ""
        
        $choices.EnableMicrosoftStore = Get-YesNoChoice -Title "Enable Microsoft Store?" -Description "Adds Microsoft Store to LTSC/IoT editions"
        $choices.InstallNotepad = Get-YesNoChoice -Title "Install Notepad from Store?" -Description "Modern Notepad application"
        $choices.InstallWindowsTerminal = Get-YesNoChoice -Title "Install Windows Terminal?" -Description "Modern terminal application"
        $choices.InstallCalculator = Get-YesNoChoice -Title "Install Calculator?" -Description "Windows Calculator application"
        $choices.InstallCamera = Get-YesNoChoice -Title "Install Camera?" -Description "Windows Camera application"
        $choices.InstallMediaPlayer = Get-YesNoChoice -Title "Install Media Player?" -Description "Windows Media Player"
        $choices.InstallPhotos = Get-YesNoChoice -Title "Install Photos?" -Description "Windows Photos application"
    }
    
    # Installation Phase
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "       INSTALLATION PHASE - Processing your choices         " -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    
    Start-Sleep -Seconds 2
    
    # Execute installations based on choices
    if ($choices.InstallOffice) {
        Install-Office -Method $choices.OfficeMethod
    }
    
    if ($choices.Activate) {
        Invoke-Activation -Target $choices.ActivateTarget
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
        if ($choices.EnableMicrosoftStore) {
            Enable-MicrosoftStore
        }
        
        if ($choices.InstallNotepad) {
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
    }
    
    # System Update (done last)
    if ($choices.UpdateAllSoftware) {
        Update-AllSoftware
    }
    
    # Completion
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "               Setup Completed Successfully!                " -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
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

# Run the setup
Start-Setup
