# --- [ WinRaze System Optimizer ] ---
# Author: Rohit Kr. Mandal (Alias: CyberKun)

# 1. Elevation & STA Mode
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"& '$PSCommandPath'`""
    exit
}

# 2. UI Initialization
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'White'
Clear-Host

# 3. WinRaze Gradient ASCII Art (Cyan to Deep Blue)
Write-Host " __      __.__         __________                     " -ForegroundColor Cyan
Write-Host "/  \    /  \__| ____   \______   \_____  ________ ____ " -ForegroundColor Cyan
Write-Host "\   \/\/   /  |/    \   |       _/\__  \ \___   // __ \" -ForegroundColor White
Write-Host " \        /|  |   |  \  |    |   \ / __ \_/    /\  ___/" -ForegroundColor Blue
Write-Host "  \__/\  / |__|___|  /  |____|_  /(____  /_____ \\___  >" -ForegroundColor DarkBlue
Write-Host "       \/          \/          \/      \/      \/    \/ " -ForegroundColor DarkBlue

Write-Host " ===================================================== " -ForegroundColor Cyan
Write-Host "   ⚡ WINRAZE SYSTEM DEVASTATOR | VERSION 1.0 ⚡      " -ForegroundColor White -BackgroundColor DarkBlue
Write-Host " ===================================================== " -ForegroundColor Cyan

# 4. Operator Identification (Anime-Style Highlighting)
Write-Host ""
Write-Host " [>] " -NoNewline -ForegroundColor White; Write-Host "OPERATOR: " -NoNewline -ForegroundColor Cyan; Write-Host "ROHIT KR. MANDAL" -NoNewline -ForegroundColor Green; Write-Host " (CyberKun)" -ForegroundColor Gray
Write-Host " [>] " -NoNewline -ForegroundColor White; Write-Host "ACCESS  : " -NoNewline -ForegroundColor Cyan; Write-Host "S-RANK ADMINISTRATOR" -ForegroundColor Green
Write-Host " [>] " -NoNewline -ForegroundColor White; Write-Host "OBJECT  : " -NoNewline -ForegroundColor Cyan; Write-Host "TOTAL SYSTEM RAZE" -ForegroundColor Red

# Fake "Loading" for Hacker Effect
Write-Host ""
Write-Host -NoNewline "[*] INITIALIZING RAZE PROTOCOLS..." -ForegroundColor Yellow
1..15 | ForEach-Object { Write-Host -NoNewline "." -ForegroundColor Yellow; Start-Sleep -Milliseconds 50 }
Write-Host " [ONLINE]" -ForegroundColor Green
Write-Host "-----------------------------------------------------" -ForegroundColor Gray
Pause
# Force Dark Mode for System UI and Apps
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0

# Set Black as Accent Color (for title bars)
Set-ItemProperty -Path "HKCU:\Control Panel\Colors" -Name "AccentColor" -Type String -Value "0 0 0 0"
Set-ItemProperty -Path "HKCU:\Control Panel\Colors" -Name "AccentColorInactive" -Type String -Value "0 0 0 0"

# Optional: Disable Transparency Effects for Taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0

# Set GPU Priority to 0 (Not playing games)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPUPriority" -Value 0

# Set SystemResponsiveness to 0 for better multimedia performance
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0

# Disable Animations
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x00,0x10,0x00,0x00,0x00,0x00,0x00))
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value "0"

# Disable Windows Hibernation (Free Up Disk Space)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Value 0

# Disable Thumbnails (Speed Up File Explorer)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Value 1

# Disable Windows Ink Workspace
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "Enabled" -Value 0

# Disable System Sounds
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default" -Name "SystemAsterisk" -Value ""
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default" -Name "SystemExclamation" -Value ""
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default" -Name "SystemHand" -Value ""

# Speed Up File Explorer
Set-ItemProperty -Path "HKCR:\Directory\Background" -Name "Coalesce" -Value "1"
Set-ItemProperty -Path "HKCR:\Directory\Background" -Name "NoDDE" -Value "1"
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Set-ItemProperty -Path $RegistryPath -Name "LaunchTo" -Value 1

# Disable Low Disk Space Warning
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoLowDiskSpaceChecks" -Value 1

# Optimize Windows Prefetch and Superfetch
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PrefetchParameters" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name "Start" -Value 4

# Increase Network Performance
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpDelAckTicks" -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUBHDetect" -Value 0

# Set NetworkThrottlingIndex to 0xffffffff for better network performance
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff

# ---------------------------------------------------------
# Ultimate "Strict" Windows Service Manager
# ---------------------------------------------------------

# Function to strictly Apply Settings
function Set-ServiceState {
    param([string[]]$ServiceList, [string]$State)
    foreach ($name in $ServiceList) {
        try {
            $service = Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($null -eq $service) { continue } 

            if ($State -eq "Enable") {
                Write-Host "Enabling $name..." -ForegroundColor Cyan
                Set-Service -Name $name -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name $name -ErrorAction SilentlyContinue
            } else {
                Write-Host "Strictly Disabling $name..." -ForegroundColor Gray
                Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $name -StartupType Disabled -ErrorAction SilentlyContinue
            }
        } catch { }
    }
}

Clear-Host
Write-Host "--- Windows Service Optimization Script ---" -ForegroundColor White
Write-Host "This script will strictly DISABLE services based on your choices." -ForegroundColor Yellow
Write-Host "------------------------------------------------------------"

# 1. ALWAYS DISABLE (The "Safe" List - Privacy, Telemetry, and Bloat)
$bloat = @(
    "WSearch", "AxInstSV", "MapsBroker", "DiagTrack", "WerSvc", "dmwappushservice", 
    "Fax", "PhoneSvc", "RetailDemo", "workfolderssvc", "AssignedAccessManagerSvc", 
    "diagsvc", "DPS", "WdiServiceHost", "WdiSystemHost", "lfsvc", "SensorService", 
    "SensorDataService", "SensrSvc", "TrkWks", "fhsvc", "XblAuthManager", 
    "XblGameSave", "XboxNetApiSvc", "XboxGipSvc", "BcastDVRUserService_*",
    "HvHost", "vmickvpexchange", "vmicguestinterface", "vmicshutdown", 
    "vmicheartbeat", "vmicvmsession", "vmicrdv", "vmictimesync", "vmicvss" , "BDESVC"
)
Write-Host "[*] Automatically disabling background bloat and telemetry..." -ForegroundColor Cyan
Set-ServiceState -ServiceList $bloat -State "Disable"

# 2. REMOTE DESKTOP ACCESS
$rdpChoice = Read-Host "Do you use Remote Desktop (Control this PC from another device)? (Y/N)"
if ($rdpChoice -eq "N") {
    Set-ServiceState -ServiceList @("TermService", "SessionEnv", "UmRdpService", "RemoteRegistry") -State "Disable"
}

# 3. PRINTERS
$printChoice = Read-Host "Do you use a Printer? (Y/N)"
if ($printChoice -eq "N") {
    Set-ServiceState -ServiceList @("Spooler", "PrintNotify") -State "Disable"
}

# 4. TOUCH KEYBOARD & HANDWRITING
$touchChoice = Read-Host "Do you use a Touch Screen or Stylus Pen? (Y/N)"
if ($touchChoice -eq "N") {
    Set-ServiceState -ServiceList @("TabletInputService") -State "Disable"
}

# 5. BLUETOOTH
$btChoice = Read-Host "Do you use Bluetooth (Mouse, Keyboard, or Headphones)? (Y/N)"
if ($btChoice -eq "N") {
    Set-ServiceState -ServiceList @("bthserv", "BTAGService", "BthAvctpSvc", "BluetoothUserService_*") -State "Disable"
}
elseif ($btChoice -eq "Y") {
    Set-ServiceState -ServiceList @("bthserv", "BTAGService", "BthAvctpSvc", "BluetoothUserService_*") -State "Enable"
}
else {
    Write-Host "Invalid choice. Please enter Y or N."
}

# 6. BIOMETRICS
$bioChoice = Read-Host "Do you use Fingerprint or Face ID to login? (Y/N)"
if ($bioChoice -eq "N") {
    Set-ServiceState -ServiceList @("WbioSrvc") -State "Disable"
}

# 7. MICROSOFT STORE
$storeChoice = Read-Host "Do you use the Microsoft Store and Store Apps (Calculator/Photos)? (Y/N)"
if ($storeChoice -eq "Y") {
    Set-ServiceState -ServiceList @("AppXSvc", "StoreSvc", "ClipSVC", "LicenseManager") -State "Enable"
} else {
    Set-ServiceState -ServiceList @("AppXSvc", "StoreSvc", "ClipSVC", "LicenseManager") -State "Disable"
}

# 8. WINDOWS UPDATE & SECURITY
$wuChoice = Read-Host "Do you want to keep Windows Update and BitLocker Security? (Y/N)"
if ($wuChoice -eq "Y") {
    Set-ServiceState -ServiceList @("wuauserv", "UsoSvc", "BITS", "BDESVC") -State "Enable"
} else {
    Set-ServiceState -ServiceList @("wuauserv", "UsoSvc", "BITS", "BDESVC", "WaaSMedicSvc") -State "Disable"
}

# 9. NETWORKING HELPERS (IPv6 & Netlogon)
$netChoice = Read-Host "Disable advanced Networking (IPv6 Helper/Netlogon)? (Y/N)"
if ($netChoice -eq "Y") {
    Set-ServiceState -ServiceList @("iphlpsvc", "Netlogon") -State "Disable"
}

Write-Host "`nConfiguration Complete! Please Restart your PC for changes to take effect." -ForegroundColor Green
Pause

# Ask the user if they want to enable or disable camera and microphone access
$choice = Read-Host "Do you want Camera & Microphone? (Y/N)"

if ($choice -eq "Y") {
    Write-Output "--- Enabling Camera and Microphone Permanently ---"

    # Enable Camera
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -Name "Value" -ErrorAction SilentlyContinue

    # Enable Microphone
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" -Name "Value" -ErrorAction SilentlyContinue
    Write-Output "Camera and microphone have been permanently enabled."

    # Restore Permissions to Allow Future Changes
    icacls "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /grant Administrators:F
    icacls "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /grant Administrators:F
    icacls "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /grant Administrators:F
}
elseif ($choice -eq "N") {
    Write-Output "--- Disabling Camera and Microphone Permanently ---"

    # Disable Camera
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -Value 2 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Value "Deny" -Type String
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" -Name "Value" -Value "Deny" -Type String

    # Disable Microphone
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -Value 2 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Value "Deny" -Type String
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" -Name "Value" -Value "Deny" -Type String

    Write-Output "Camera and microphone have been permanently disabled."

    # Lock Registry Modifications to Prevent Any Changes
    icacls "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /deny Administrators:F
    icacls "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /deny Administrators:F
    icacls "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /deny Administrators:F
}
else {
    Write-Output "Invalid input. Please enter 'Y' to enable or 'N' to disable."
}

# --- Notification Privacy Choice ---
$notifChoice = Read-Host "Do you want App Notifications? (Y/N)"

if ($notifChoice -eq "Y") {
    Write-Output "--- Enabling App Notifications ---"

    # 1. Clear Policy Restrictions
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -ErrorAction SilentlyContinue
    
    # 2. Set ConsentStore to Allow
    $notifPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"
    if (Test-Path $notifPath) {
        Set-ItemProperty -Path $notifPath -Name "Value" -Value "Allow"
    }

    # 3. Clear Legacy GUID Restriction
    Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" -Name "Value" -ErrorAction SilentlyContinue

    Write-Output "Notifications have been enabled."
}
elseif ($notifChoice -eq "N") {
    Write-Output "--- Disabling App Notifications ---"

    # 1. Apply Policy Restriction (Value 2 = Force Deny)
    $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
    if (-Not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessNotifications" -Value 2 -Type DWord

    # 2. Set ConsentStore to Deny
    $notifPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"
    if (-Not (Test-Path $notifPath)) { New-Item -Path $notifPath -Force | Out-Null }
    Set-ItemProperty -Path $notifPath -Name "Value" -Value "Deny" -Type String

    # 3. Disable Legacy GUID Access
    $guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}"
    if (-Not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny" -Type String

    Write-Output "Notifications have been disabled."
}
else {
    Write-Output "Invalid input. Skipping Notification settings."
}

# To remove default folders from "This PC"
$confirmation = Read-Host "Do you want to remove 'This PC' default folders? (Y/N)"

if ($confirmation -eq 'Y') {
$keysToRemove = @(
    # Desktop
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",

    # Documents
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}",

    # Downloads
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}",

    # Music
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}",

    # Pictures
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}",

    # Videos
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}",

    # 3D Objects
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
)
foreach ($key in $keysToRemove) {
        try {
            Remove-Item -Path $key -Force -ErrorAction Stop
            Write-Host "Removed: $key"
        } catch {
            Write-Host "Not found or failed: $key"
        }
    }
} else {
    Write-Host "Operation cancelled."
}

# Disable Xbox Game Bar
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -ErrorAction SilentlyContinue

# Turn off background recording
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -ErrorAction SilentlyContinue


# Disable Record Audio in Captures (Game DVR settings)
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0 -ErrorAction SilentlyContinue

# Disable app access to "Documents" folder
Write-Output "--- Disabling app access to 'Documents' folder ---"
$documentsKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary'
$data = 'Deny'

If (-Not (Test-Path $documentsKeyPath)) {
    New-Item -Path $documentsKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $documentsKeyPath -Name 'Value' -Value $data
Write-Output "Access to 'Documents' folder has been set to 'Deny'."

# Disable app access to "Pictures" folder
Write-Output "--- Disabling app access to 'Pictures' folder ---"
$picturesKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary'

If (-Not (Test-Path $picturesKeyPath)) {
    New-Item -Path $picturesKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $picturesKeyPath -Name 'Value' -Value $data
Write-Output "Access to 'Pictures' folder has been set to 'Deny'."

# Disable app access to "Videos" folder
Write-Output "--- Disabling app access to 'Videos' folder ---"
$videosKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary'
$data = 'Deny'

If (-Not (Test-Path $videosKeyPath)) {
    New-Item -Path $videosKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $videosKeyPath -Name 'Value' -Value $data
Write-Output "Access to 'Videos' folder has been set to 'Deny'."

# Disable app access to "Music" folder
Write-Output "--- Disabling app access to 'Music' folder ---"
$musicKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary'

If (-Not (Test-Path $musicKeyPath)) {
    New-Item -Path $musicKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $musicKeyPath -Name 'Value' -Value $data
Write-Output "Access to 'Music' folder has been set to 'Deny'."

# Disable app access to "Personal Files"
Write-Output "--- Disabling app access to 'Personal Files' ---"
$broadFileSystemAccessKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess'
$data = 'Deny'

If (-Not (Test-Path $broadFileSystemAccessKeyPath)) {
    New-Item -Path $broadFileSystemAccessKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $broadFileSystemAccessKeyPath -Name 'Value' -Value $data
Write-Output "Access to 'Personal Files' has been set to 'Deny'."

# Disable app access to "Call History"
Write-Output "--- Disabling app access to 'Call History' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessCallHistory' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessCallHistory' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessCallHistory_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessCallHistory_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessCallHistory_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Call History' settings has been modified through GPO."

# Disable app capability for 'phoneCallHistory'
$phoneCallHistoryKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory'
If (-Not (Test-Path $phoneCallHistoryKeyPath)) {
    New-Item -Path $phoneCallHistoryKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $phoneCallHistoryKeyPath -Name 'Value' -Value $data
Write-Output "Access to 'phoneCallHistory' has been set to 'Deny'."

# Disable app access in older Windows versions (before 1903)
Write-Output "--- Disabling app access to GUID {8BC668CF-7728-45BD-93F8-CF2B3B41D7AB} ---"
$oldWindowsKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}'
If (-Not (Test-Path $oldWindowsKeyPath)) {
    New-Item -Path $oldWindowsKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $oldWindowsKeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID has been set to 'Deny'."

# Disable app access to phone calls
Write-Output "--- Disabling app access to 'Phone Calls' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessPhone' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessPhone' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessPhone_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessPhone_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessPhone_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Phone Calls' settings has been modified through GPO."

# Disable app capability for 'phoneCall'
$phoneCallKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall'
$data = 'Deny'

If (-Not (Test-Path $phoneCallKeyPath)) {
    New-Item -Path $phoneCallKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $phoneCallKeyPath -Name 'Value' -Value $data
Write-Output "Access to 'phoneCall' has been set to 'Deny'."


# Disable app access to messaging (SMS/MMS)
Write-Output "--- Disabling app access to 'Messaging (SMS/MMS)' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessMessaging' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessMessaging' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessMessaging_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessMessaging_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessMessaging_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Messaging (SMS/MMS)' settings has been modified through GPO."

# Disable app capability for 'chat'
$chatKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat'
$data = 'Deny'

If (-Not (Test-Path $chatKeyPath)) {
    New-Item -Path $chatKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $chatKeyPath -Name 'Value' -Value $data
Write-Output "Access to 'Chat' has been set to 'Deny'."

# Disable app access in older Windows versions (before 1903) - {992AFA70-6F47-4148-B3E9-3003349C1548}
Write-Output "--- Disabling app access to GUID {992AFA70-6F47-4148-B3E9-3003349C1548} ---"
$guid1KeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}'
If (-Not (Test-Path $guid1KeyPath)) {
    New-Item -Path $guid1KeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $guid1KeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID {992AFA70-6F47-4148-B3E9-3003349C1548} has been set to 'Deny'."

# Disable app access in older Windows versions (before 1903) - {21157C1F-2651-4CC1-90CA-1F28B02263F6}
Write-Output "--- Disabling app access to GUID {21157C1F-2651-4CC1-90CA-1F28B02263F6} ---"
$guid2KeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}'
If (-Not (Test-Path $guid2KeyPath)) {
    New-Item -Path $guid2KeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $guid2KeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID {21157C1F-2651-4CC1-90CA-1F28B02263F6} has been set to 'Deny'."

# Disable app access to paired Bluetooth devices
Write-Output "--- Disabling app access to 'Paired Bluetooth Devices' ---"
$bluetoothKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth'
$data = 'Deny'

If (-Not (Test-Path $bluetoothKeyPath)) {
    New-Item -Path $bluetoothKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $bluetoothKeyPath -Name 'Value' -Value $data
Write-Output "Access to 'Paired Bluetooth Devices' has been set to 'Deny'."

# Disable app access to unpaired Bluetooth devices
Write-Output "--- Disabling app access to 'Unpaired Bluetooth Devices' ---"
$bluetoothSyncKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync'

If (-Not (Test-Path $bluetoothSyncKeyPath)) {
    New-Item -Path $bluetoothSyncKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $bluetoothSyncKeyPath -Name 'Value' -Value $data
Write-Output "Access to 'Unpaired Bluetooth Devices' has been set to 'Deny'."

# Disable app access to voice activation
Write-Output "--- Disabling app access to 'Voice Activation' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsActivateWithVoice' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsActivateWithVoice' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsActivateWithVoice_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsActivateWithVoice_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsActivateWithVoice_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Voice Activation' settings has been modified through GPO."

# Disable voice activation for all apps
$voiceActivationKeyPath = 'HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps'
$data = 0

If (-Not (Test-Path $voiceActivationKeyPath)) {
    New-Item -Path $voiceActivationKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $voiceActivationKeyPath -Name 'AgentActivationEnabled' -Value $data -Type DWord
Write-Output "Voice activation has been disabled for all apps."

# Disable app access to voice activation on locked system
Write-Output "--- Disabling app access to 'Voice Activation on Locked System' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsActivateWithVoiceAboveLock' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsActivateWithVoiceAboveLock' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsActivateWithVoiceAboveLock_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsActivateWithVoiceAboveLock_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsActivateWithVoiceAboveLock_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Voice Activation Above Lock' settings has been modified through GPO."

# Disable voice activation on locked system for all apps
$voiceActivationKeyPath = 'HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps'
$data = 0

If (-Not (Test-Path $voiceActivationKeyPath)) {
    New-Item -Path $voiceActivationKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $voiceActivationKeyPath -Name 'AgentActivationOnLockScreenEnabled' -Value $data -Type DWord
Write-Output "Voice activation on lock screen has been disabled for all apps."

# Disable app access to location
Write-Output "--- Disabling app access to 'Location' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessLocation' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessLocation' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessLocation_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessLocation_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessLocation_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Location' settings has been modified through GPO."

# Disable location capability
$locationKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
$data = 'Deny'

If (-Not (Test-Path $locationKeyPath)) {
    New-Item -Path $locationKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $locationKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Location' access has been set to 'Deny'."

# Disable location services configuration
$lfsvcKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration'
$configData = 0

If (-Not (Test-Path $lfsvcKeyPath)) {
    New-Item -Path $lfsvcKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $lfsvcKeyPath -Name 'Status' -Value $configData -Type DWord
Write-Output "Location services status has been disabled."

# Disable location access in older Windows versions - {BFA794E4-F964-4FDB-90F6-51056BFE4B44}
Write-Output "--- Disabling app access to GUID {BFA794E4-F964-4FDB-90F6-51056BFE4B44} ---"
$guid1KeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}'
If (-Not (Test-Path $guid1KeyPath)) {
    New-Item -Path $guid1KeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $guid1KeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID {BFA794E4-F964-4FDB-90F6-51056BFE4B44} has been set to 'Deny'."

# Disable location access in older Windows versions - {E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}
Write-Output "--- Disabling app access to GUID {E6AD100E-5F4E-44CD-BE0F-2265D88D14F5} ---"
$guid2KeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}'
If (-Not (Test-Path $guid2KeyPath)) {
    New-Item -Path $guid2KeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $guid2KeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID {E6AD100E-5F4E-44CD-BE0F-2265D88D14F5} has been set to 'Deny'."

# Disable app access to account information, name, and picture
Write-Output "--- Disabling app access to 'Account Information, Name, and Picture' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessAccountInfo' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessAccountInfo' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessAccountInfo_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessAccountInfo_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessAccountInfo_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Account Information' settings has been modified through GPO."

# Disable userAccountInformation capability
$userAccountInfoKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation'
$data = 'Deny'

If (-Not (Test-Path $userAccountInfoKeyPath)) {
    New-Item -Path $userAccountInfoKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $userAccountInfoKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'userAccountInformation' access has been set to 'Deny'."

# Disable account information access in older Windows versions - {C1D23ACC-752B-43E5-8448-8D0E519CD6D6}
Write-Output "--- Disabling app access to GUID {C1D23ACC-752B-43E5-8448-8D0E519CD6D6} ---"
$guidKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}'
If (-Not (Test-Path $guidKeyPath)) {
    New-Item -Path $guidKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $guidKeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID {C1D23ACC-752B-43E5-8448-8D0E519CD6D6} has been set to 'Deny'."

# Disable app access to motion activity
Write-Output "--- Disabling app access to 'Motion Activity' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessMotion' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessMotion' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessMotion_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessMotion_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessMotion_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Motion Activity' settings has been modified through GPO."

# Disable motion activity capability
$activityKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity'
$data = 'Deny'

If (-Not (Test-Path $activityKeyPath)) {
    New-Item -Path $activityKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $activityKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Motion Activity' access has been set to 'Deny'."

# Disable app access to trusted devices
Write-Output "--- Disabling app access to 'Trusted Devices' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessTrustedDevices' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessTrustedDevices' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessTrustedDevices_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessTrustedDevices_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessTrustedDevices_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Trusted Devices' settings has been modified through GPO."

# Disable app access to unpaired wireless devices
Write-Output "--- Disabling app access to 'Unpaired Wireless Devices' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsSyncWithDevices' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsSyncWithDevices' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsSyncWithDevices_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsSyncWithDevices_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsSyncWithDevices_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Unpaired Wireless Devices' settings has been modified through GPO."

# Disable unpaired wireless device access in older Windows versions - LooselyCoupled
Write-Output "--- Disabling app access to 'Loosely Coupled' devices for older Windows versions ---"
$looselyCoupledKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled'
$data = 'Deny'

If (-Not (Test-Path $looselyCoupledKeyPath)) {
    New-Item -Path $looselyCoupledKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $looselyCoupledKeyPath -Name 'Value' -Value $data
Write-Output "Access to 'Loosely Coupled' devices has been set to 'Deny'."


# Disable app access to information about other apps
Write-Output "--- Disabling app access to 'Information About Other Apps' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsGetDiagnosticInfo' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsGetDiagnosticInfo' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsGetDiagnosticInfo_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsGetDiagnosticInfo_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsGetDiagnosticInfo_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Diagnostic Information' settings has been modified through GPO."

# Disable appDiagnostics capability
$appDiagnosticsKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics'
$data = 'Deny'

If (-Not (Test-Path $appDiagnosticsKeyPath)) {
    New-Item -Path $appDiagnosticsKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $appDiagnosticsKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'App Diagnostics' access has been set to 'Deny'."

# Disable diagnostic information access in older Windows versions - {2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}
Write-Output "--- Disabling app access to GUID {2297E4E2-5DBE-466D-A12B-0F8286F0D9CA} ---"
$guidKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}'

If (-Not (Test-Path $guidKeyPath)) {
    New-Item -Path $guidKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $guidKeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID {2297E4E2-5DBE-466D-A12B-0F8286F0D9CA} has been set to 'Deny'."

# Disable app access to contacts
Write-Output "--- Disabling app access to 'Contacts' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessContacts' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessContacts' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessContacts_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessContacts_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessContacts_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Contacts' settings has been modified through GPO."

# Disable contacts capability
$contactsKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts'
$data = 'Deny'

If (-Not (Test-Path $contactsKeyPath)) {
    New-Item -Path $contactsKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $contactsKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Contacts' access has been set to 'Deny'."

# Disable contacts access in older Windows versions - {7D7E8402-7C54-4821-A34E-AEEFD62DED93}
Write-Output "--- Disabling app access to GUID {7D7E8402-7C54-4821-A34E-AEEFD62DED93} ---"
$guidKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}'

If (-Not (Test-Path $guidKeyPath)) {
    New-Item -Path $guidKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $guidKeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID {7D7E8402-7C54-4821-A34E-AEEFD62DED93} has been set to 'Deny'."



# Disable app access to calendar
Write-Output "--- Disabling app access to 'Calendar' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessCalendar' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessCalendar' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessCalendar_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessCalendar_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessCalendar_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Calendar' settings has been modified through GPO."

# Disable calendar capability
$appointmentsKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments'
$data = 'Deny'

If (-Not (Test-Path $appointmentsKeyPath)) {
    New-Item -Path $appointmentsKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $appointmentsKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Appointments' access has been set to 'Deny'."

# Disable calendar access in older Windows versions - {D89823BA-7180-4B81-B50C-7E471E6121A3}
Write-Output "--- Disabling app access to GUID {D89823BA-7180-4B81-B50C-7E471E6121A3} ---"
$guidKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}'

If (-Not (Test-Path $guidKeyPath)) {
    New-Item -Path $guidKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $guidKeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID {D89823BA-7180-4B81-B50C-7E471E6121A3} has been set to 'Deny'."

# Disable app access to email
Write-Output "--- Disabling app access to 'Email' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessEmail' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessEmail' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessEmail_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessEmail_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessEmail_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Email' settings has been modified through GPO."

# Disable email capability
$emailKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email'
$data = 'Deny'

If (-Not (Test-Path $emailKeyPath)) {
    New-Item -Path $emailKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $emailKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Email' access has been set to 'Deny'."

# Disable email access in older Windows versions - {9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}
Write-Output "--- Disabling app access to GUID {9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5} ---"
$guidKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}'

If (-Not (Test-Path $guidKeyPath)) {
    New-Item -Path $guidKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $guidKeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID {9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5} has been set to 'Deny'."

# Disable app access to tasks
Write-Output "--- Disabling app access to 'Tasks' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessTasks' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessTasks' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessTasks_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessTasks_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessTasks_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Tasks' settings has been modified through GPO."

# Disable userDataTasks capability
$userDataTasksKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks'
$data = 'Deny'

If (-Not (Test-Path $userDataTasksKeyPath)) {
    New-Item -Path $userDataTasksKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $userDataTasksKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'userDataTasks' access has been set to 'Deny'."

# Disable tasks access in older Windows versions - {E390DF20-07DF-446D-B962-F5C953062741}
Write-Output "--- Disabling app access to GUID {E390DF20-07DF-446D-B962-F5C953062741} ---"
$guidKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}'

If (-Not (Test-Path $guidKeyPath)) {
    New-Item -Path $guidKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $guidKeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID {E390DF20-07DF-446D-B962-F5C953062741} has been set to 'Deny'."

# Disable app access to radios
Write-Output "--- Disabling app access to 'Radios' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessRadios' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessRadios' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessRadios_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessRadios_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessRadios_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Radios' settings has been modified through GPO."

# Disable radios capability
$radiosKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios'
$data = 'Deny'

If (-Not (Test-Path $radiosKeyPath)) {
    New-Item -Path $radiosKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $radiosKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Radios' access has been set to 'Deny'."

# Disable radios access in older Windows versions - {A8804298-2D5F-42E3-9531-9C8C39EB29CE}
Write-Output "--- Disabling app access to GUID {A8804298-2D5F-42E3-9531-9C8C39EB29CE} ---"
$guidKeyPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}'

If (-Not (Test-Path $guidKeyPath)) {
    New-Item -Path $guidKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $guidKeyPath -Name 'Value' -Value $data
Write-Output "Access to GUID {A8804298-2D5F-42E3-9531-9C8C39EB29CE} has been set to 'Deny'."

# Disable app access to physical movement
Write-Output "--- Disabling app access to 'Physical Movement' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessBackgroundSpatialPerception' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessBackgroundSpatialPerception' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessBackgroundSpatialPerception_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessBackgroundSpatialPerception_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessBackgroundSpatialPerception_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Background Spatial Perception' settings has been modified through GPO."

# Disable spatialPerception capability
$spatialPerceptionKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\spatialPerception'
$data = 'Deny'

If (-Not (Test-Path $spatialPerceptionKeyPath)) {
    New-Item -Path $spatialPerceptionKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $spatialPerceptionKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Spatial Perception' access has been set to 'Deny'."

# Disable backgroundSpatialPerception capability
$backgroundSpatialPerceptionKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\backgroundSpatialPerception'

If (-Not (Test-Path $backgroundSpatialPerceptionKeyPath)) {
    New-Item -Path $backgroundSpatialPerceptionKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $backgroundSpatialPerceptionKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Background Spatial Perception' access has been set to 'Deny'."

# Disable app access to eye tracking
Write-Output "--- Disabling app access to 'Eye Tracking' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessGazeInput' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGazeInput' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGazeInput_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGazeInput_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGazeInput_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Eye Tracking' settings has been modified through GPO."

# Disable gazeInput capability
$gazeInputKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput'
$data = 'Deny'

If (-Not (Test-Path $gazeInputKeyPath)) {
    New-Item -Path $gazeInputKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $gazeInputKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Gaze Input' access has been set to 'Deny'."

# Disable app access to human presence
Write-Output "--- Disabling app access to 'Human Presence' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessHumanPresence' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessHumanPresence' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessHumanPresence_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessHumanPresence_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessHumanPresence_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Human Presence' settings has been modified through GPO."

# Disable humanPresence capability
$humanPresenceKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanPresence'
$data = 'Deny'

If (-Not (Test-Path $humanPresenceKeyPath)) {
    New-Item -Path $humanPresenceKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $humanPresenceKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Human Presence' access has been set to 'Deny'."

# Disable app access to screen capture (GraphicsCaptureProgrammatic)
Write-Output "--- Disabling app access to 'Graphics Capture Programmatic' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsAccessGraphicsCaptureProgrammatic' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGraphicsCaptureProgrammatic' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGraphicsCaptureProgrammatic_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGraphicsCaptureProgrammatic_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGraphicsCaptureProgrammatic_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Graphics Capture Programmatic' settings has been modified through GPO."

# Disable graphicsCaptureProgrammatic capability
$graphicsCaptureProgrammaticKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic'
$data = 'Deny'

If (-Not (Test-Path $graphicsCaptureProgrammaticKeyPath)) {
    New-Item -Path $graphicsCaptureProgrammaticKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $graphicsCaptureProgrammaticKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Graphics Capture Programmatic' access has been set to 'Deny'."

# Disable app access to screen capture without borders (GraphicsCaptureWithoutBorder)
Write-Output "--- Disabling app access to 'Graphics Capture Without Borders' ---"
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGraphicsCaptureWithoutBorder' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGraphicsCaptureWithoutBorder_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGraphicsCaptureWithoutBorder_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsAccessGraphicsCaptureWithoutBorder_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Graphics Capture Without Borders' settings has been modified through GPO."

# Disable graphicsCaptureWithoutBorder capability
$graphicsCaptureWithoutBorderKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder'

If (-Not (Test-Path $graphicsCaptureWithoutBorderKeyPath)) {
    New-Item -Path $graphicsCaptureWithoutBorderKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $graphicsCaptureWithoutBorderKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Graphics Capture Without Borders' access has been set to 'Deny'."

# Disable app access to background activity
Write-Output "--- Disabling app access to 'Background Activity' ---"
$appPrivacyKeyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'

If (-Not (Test-Path $appPrivacyKeyPath)) {
    New-Item -Path $appPrivacyKeyPath -ItemType Directory | Out-Null
}

# Set 'LetAppsRunInBackground' to '2'
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsRunInBackground' -Value 2 -Type DWord
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsRunInBackground_UserInControlOfTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsRunInBackground_ForceAllowTheseApps' -Value $null -Type MultiString
Set-ItemProperty -Path $appPrivacyKeyPath -Name 'LetAppsRunInBackground_ForceDenyTheseApps' -Value $null -Type MultiString
Write-Output "Access to 'Background Activity' settings has been modified through GPO."

# Disable global user background activity
$backgroundAccessKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
$data = 1

If (-Not (Test-Path $backgroundAccessKeyPath)) {
    New-Item -Path $backgroundAccessKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $backgroundAccessKeyPath -Name 'GlobalUserDisabled' -Value $data -Type DWord
Write-Output "Global background activity access has been disabled."

# Disable Windows Feedback Collection

# Set "NumberOfSIUFInPeriod" to 0
$path1 = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"
New-Item -Path $path1 -Force | Out-Null
Set-ItemProperty -Path $path1 -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0

# Remove "PeriodInNanoSeconds" if it exists
if (Test-Path $path1) {
    $props = Get-ItemProperty -Path $path1
    if ($props.PSObject.Properties.Name -contains "PeriodInNanoSeconds") {
        Remove-ItemProperty -Path $path1 -Name "PeriodInNanoSeconds" -ErrorAction SilentlyContinue
        Write-Host "Removed PeriodInNanoSeconds."
    } else {
        Write-Host "Registry value 'PeriodInNanoSeconds' does not exist."
    }
} else {
    Write-Host "Registry key does not exist, skipping removal."
}

# Set "DoNotShowFeedbackNotifications" to 1 in system policy keys
$path2 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
New-Item -Path $path2 -Force | Out-Null
Set-ItemProperty -Path $path2 -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1

$path3 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
New-Item -Path $path3 -Force | Out-Null
Set-ItemProperty -Path $path3 -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1

Write-Host "Feedback collection has been disabled successfully."

# Disable Text and Handwriting Data Collection
$registryChanges = @(
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "RestrictImplicitInkCollection"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "RestrictImplicitTextCollection"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"; Name = "PreventHandwritingErrorReports"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"; Name = "PreventHandwritingDataSharing"; Value = 1 },
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"; Name = "AllowInputPersonalization"; Value = 0 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"; Name = "HarvestContacts"; Value = 0 },

    # Disable Activity Feed
    @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"; Name = "EnableActivityFeed"; Value = 0 },

    # Disable Typing Feedback
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Input\TIPC"; Name = "Enabled"; Value = 0 },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Input\TIPC"; Name = "Enabled"; Value = 0 },

    # Opt Out of Windows Privacy Consent
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"; Name = "AcceptedPrivacyPolicy"; Value = 0 }
)

foreach ($change in $registryChanges) {
    if (-not (Test-Path $change.Path)) {
        New-Item -Path $change.Path -Force | Out-Null
    }
    Set-ItemProperty -Path $change.Path -Name $change.Name -Value $change.Value -Type DWord
    Write-Host "Set $($change.Path)\$($change.Name) to $($change.Value)"
}

# To disable Multitasking
# Snap Assist and all snapping behaviors
$advancedPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Set-ItemProperty -Path $advancedPath -Name "SnapAssist" -Value 0
Set-ItemProperty -Path $advancedPath -Name "SnapFill" -Value 0
Set-ItemProperty -Path $advancedPath -Name "SnapAutoArrange" -Value 0
Set-ItemProperty -Path $advancedPath -Name "SnapInvoked" -Value 0

# Multitasking registry settings (Windows 10/11)
$multiTaskPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MultitaskingView"

# Hide Timeline and Task View (Virtual Desktops UI)
Set-ItemProperty -Path $advancedPath -Name "ShowTaskViewButton" -Value 0

# Alt+Tab behavior – prevent showing Edge tabs or windows
Set-ItemProperty -Path $advancedPath -Name "MultiTaskingAltTabFilter" -Value 3

# Disable Task View background saving (Timeline)
$systemPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
New-Item -Path $systemPolicyPath -Force | Out-Null
Set-ItemProperty -Path $systemPolicyPath -Name "EnableActivityFeed" -Value 0 -Force
Set-ItemProperty -Path $systemPolicyPath -Name "PublishUserActivities" -Value 0 -Force
Set-ItemProperty -Path $systemPolicyPath -Name "UploadUserActivities" -Value 0 -Force

# Optional: remove "Desktops" from Taskbar (Win11+)
$taskbarRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Set-ItemProperty -Path $taskbarRegPath -Name "ShowTaskViewButton" -Value 0

# Optional: disable Windows snapping hotkeys (Win + Left/Right)
# No direct registry key; can block via group policies or third-party tools only

# Optional: disable Virtual Desktops hotkeys (Win+Ctrl+D, Win+Ctrl+Left/Right)
# Again, no native registry flag; must be blocked via intercepting input (3rd party)

# Disable Snap Windows (main toggle)
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WindowArrangementActive" -Value 0

# Disable Snap Assist
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SnapAssist" -Value 0

# Disable Snap Fill
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SnapFill" -Value 0

# Disable Joint Resize
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "JointResize" -Value 0
Write-Output "--- FInally Multitasking Toggles turned off ---"

# Disable app access to input devices
Write-Output "--- Disabling app access to 'Input Devices' ---"
$humanInterfaceDeviceKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice'
$data = 'Deny'

If (-Not (Test-Path $humanInterfaceDeviceKeyPath)) {
    New-Item -Path $humanInterfaceDeviceKeyPath -ItemType Directory | Out-Null
}
Set-ItemProperty -Path $humanInterfaceDeviceKeyPath -Name 'Value' -Value $data
Write-Output "Capability 'Human Interface Device' access has been set to 'Deny'."

# Onedrive 

# --- OneDrive Permanent Removal Script ---

# Kill the OneDrive process
Write-Host "--- Killing OneDrive process ---"
$process = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
if ($process) {
    Write-Host "OneDrive is running and will be terminated."
    Stop-Process -Name "OneDrive" -Force
} else {
    Write-Host "Skipping, OneDrive is not running."
}

# Remove OneDrive from startup
Write-Host "--- Removing OneDrive from startup ---"
$keyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$valueName = "OneDrive"
if (Test-Path $keyPath) {
    Remove-ItemProperty -Path $keyPath -Name $valueName -ErrorAction SilentlyContinue
    Write-Host "OneDrive startup entry removed."
} else {
    Write-Host "Registry key does not exist."
}

# Uninstall OneDrive using the official installer
Write-Host "--- Uninstalling OneDrive ---"
$installerPaths = @("$env:SYSTEMROOT\System32\OneDriveSetup.exe", "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe")
$installer = $installerPaths | Where-Object { Test-Path $_ }
if ($installer) {
    & $installer /uninstall
    Write-Host "OneDrive uninstalled using $installer."
} else {
    Write-Host "Installer not found."
}

# Remove OneDrive directories and files
Write-Host "--- Removing OneDrive data directories ---"
$directories = @(
    "$env:USERPROFILE\OneDrive",
    "$env:LOCALAPPDATA\Microsoft\OneDrive",
    "$env:PROGRAMDATA\Microsoft OneDrive",
    "$env:SystemDrive\OneDriveTemp"
)
foreach ($directory in $directories) {
    if (Test-Path $directory) {
        Remove-Item -Path $directory -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "Removed $directory."
    } else {
        Write-Host "$directory not found."
    }
}

# Remove OneDrive shortcuts
Write-Host "--- Removing OneDrive shortcuts ---"
$shortcuts = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk",
    "$env:USERPROFILE\Links\OneDrive.lnk"
)
foreach ($shortcut in $shortcuts) {
    if (Test-Path $shortcut) {
        Remove-Item -Path $shortcut -Force -ErrorAction SilentlyContinue
        Write-Host "Removed shortcut $shortcut."
    } else {
        Write-Host "$shortcut not found."
    }
}

# Remove OneDrive registry keys
Write-Host "--- Removing OneDrive registry keys ---"
$registryKeys = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
)
foreach ($key in $registryKeys) {
    if (Test-Path $key) {
        Remove-Item -Path $key -Force -ErrorAction SilentlyContinue
        Write-Host "Removed registry key $key."
    } else {
        Write-Host "$key not found."
    }
}

# Disable OneDrive via Group Policies
Write-Host "--- Disabling OneDrive via Group Policies ---"
$keyPath = "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
New-Item -Path $keyPath -Force | Out-Null
Set-ItemProperty -Path $keyPath -Name "DisableFileSyncNGSC" -Value 1
Write-Host "Group policy to disable OneDrive set."

# Remove OneDrive from explorer sidebar
Write-Host "--- Removing OneDrive from explorer sidebar ---"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" | Out-Null
Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" | Out-Null
Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0
Remove-PSDrive "HKCR"
Write-Host "OneDrive sidebar entry removed."

# Disable OneDrive scheduled tasks
Write-Host "--- Disabling OneDrive scheduled tasks ---"
$taskPatterns = @("OneDrive Reporting Task-*", "OneDrive Standalone Update Task-*", "OneDrive*")
foreach ($taskPattern in $taskPatterns) {
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -like $taskPattern }
    foreach ($task in $tasks) {
        Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
        Write-Host "Disabled task $($task.TaskName)."
    }
}

# Remove additional OneDrive leftovers
Write-Host "--- Removing additional OneDrive leftovers ---"
foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*" -ErrorAction SilentlyContinue)) {
    Takeown-Folder $item.FullName
    Remove-Item -Path $item.FullName -Force -Recurse -ErrorAction SilentlyContinue
    Write-Host "Removed $($item.FullName)."
}

# To remove Edge permanently 2 steps must be followed
# Edge First step

# Step 1: Uninstall Microsoft Edge via AppxPackage
Write-Host "--- Uninstalling Microsoft Edge via AppxPackage ---"
$edgePackages = Get-AppxPackage *Microsoft.Edge* 2>$null
if ($edgePackages) {
    $edgePackages | Remove-AppxPackage -ErrorAction SilentlyContinue
    Write-Host "Removed Microsoft Edge App."
} else {
    Write-Host "Microsoft Edge is not installed via AppxPackage."
}

# Step 2: Uninstall Microsoft Edge via Built-in Installer
Write-Host "--- Uninstalling Microsoft Edge via Built-in Installer ---"
$edgeInstaller = "C:\Program Files (x86)\Microsoft\Edge\Application\Installer\setup.exe"
if (Test-Path $edgeInstaller) {
    Start-Process $edgeInstaller -ArgumentList "--uninstall --system-level --force-uninstall" -NoNewWindow -Wait
    Write-Host "Microsoft Edge uninstallation process initiated."
} else {
    Write-Host "Edge installer not found."
}

# Step 3: Remove Edge Application Associations
Write-Host "--- Removing Edge Application Associations ---"
$assocKeys = @(
    'MSEdgeHTM_.webp', 'MSEdgeHTM_.xml', 'MSEdgeHTM_http', 'MSEdgeHTM_https', 'MSEdgeHTM_.htm',
    'MSEdgeHTM_.html', 'MSEdgePDF_.pdf', 'MSEdgeHTM_.svg', 'MSEdgeHTM_mailto', 'MSEdgeHTM_read',
    'MSEdgeHTM_.mht', 'MSEdgeMHT_.mht', 'MSEdgeHTM_.mhtml', 'MSEdgeMHT_.mhtml', 'MSEdgeHTM_microsoft-edge'
)
foreach ($assoc in $assocKeys) {
    if (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts") {
        Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" -Name $assoc -ErrorAction SilentlyContinue
        Write-Host "Removed association for: $assoc"
    } else {
        Write-Host "Path not found for: $assoc"
    }
}

# Step 4: Remove Edge Registry Keys
Write-Host "--- Removing Microsoft Edge Registry Keys ---"
$edgeRegistryKeys = @(
    "HKCU:\Software\Microsoft\Edge",
    "HKCU:\Software\Microsoft\Edge Dev",
    "HKCU:\Software\Microsoft\Edge Beta",
    "HKLM:\Software\Microsoft\Edge",
    "HKLM:\Software\WOW6432Node\Microsoft\Edge",
    "HKLM:\Software\Microsoft\EdgeUpdate",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"
)
foreach ($key in $edgeRegistryKeys) {
    if (Test-Path $key) {
        Remove-Item -Recurse -Force $key -ErrorAction SilentlyContinue
        Write-Host "Removed registry key: $key"
    } else {
        Write-Host "Registry key not found: $key"
    }
}

# Step 5: Remove Edge Installation Folders
Write-Host "--- Removing Microsoft Edge Installation Folders ---"
$edgeFolders = @(
    "C:\Program Files (x86)\Microsoft\Edge",
    "C:\Program Files\Microsoft\Edge",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge",
    "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"
)
foreach ($folder in $edgeFolders) {
    if (Test-Path $folder) {
        Remove-Item -Recurse -Force $folder -ErrorAction SilentlyContinue
        Write-Host "Removed folder: $folder"
    } else {
        Write-Host "Folder not found: $folder"
    }
}

# Step 6: Remove Edge Shortcuts
Write-Host "--- Removing Microsoft Edge Shortcuts ---"
$edgeShortcuts = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
    "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk",
    "C:\Users\$env:USERNAME\Desktop\Microsoft Edge.lnk",
    "C:\Users\Public\Desktop\Microsoft Edge.lnk"
)
foreach ($shortcut in $edgeShortcuts) {
    if (Test-Path $shortcut) {
        Remove-Item -Force $shortcut -ErrorAction SilentlyContinue
        Write-Host "Removed shortcut: $shortcut"
    } else {
        Write-Host "Shortcut not found: $shortcut"
    }
}

# Step 7: Remove User-Specific Edge Data
Write-Host "--- Cleaning Up User-Specific Edge Data ---"
$edgeUserDataPaths = @(
    "$env:APPDATA\Microsoft\Edge",
    "$env:LOCALAPPDATA\Microsoft\Edge",
    "$env:LOCALAPPDATA\Microsoft\Edge Dev",
    "$env:LOCALAPPDATA\Microsoft\Edge Beta",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
)
foreach ($path in $edgeUserDataPaths) {
    if (Test-Path $path) {
        Remove-Item -Recurse -Force $path -ErrorAction SilentlyContinue
        Write-Host "Removed user data folder: $path"
    } else {
        Write-Host "No user data found at: $path"
    }
}

# Step 8: Remove Edge-related Services and Scheduled Tasks
Write-Host "--- Removing Edge-related Services and Tasks ---"
$edgeServices = Get-Service | Where-Object { $_.DisplayName -like "*Edge*" } 2>$null
foreach ($service in $edgeServices) {
    Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
    Write-Host "Stopped Edge-related service: $($service.Name)"
}
try {
    $scheduledTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*Edge*" }
    foreach ($task in $scheduledTasks) {
        Unregister-ScheduledTask -TaskName $task.TaskName -Force
        Write-Host "Removed scheduled task: $($task.TaskName)"
    }
} catch {
    Write-Warning "Failed to access scheduled tasks."
}

# Step 9: Block Edge Reinstallation
Write-Host "--- Blocking Microsoft Edge Reinstallation ---"
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "PreventMicrosoftEdgeRollback" -Value 1 -Type DWord
Write-Host "Microsoft Edge rollback prevention enabled."

# Edge 2nd Step for confirmation
# Remove Edge application selection associations
Write-Output "--- Removing Edge application selection associations ---"
$assocToRemove = @(
    'MSEdgeHTM_.webp', 'MSEdgeHTM_.xml', 'MSEdgeHTM_http', 'MSEdgeHTM_https', 'MSEdgeHTM_.htm',
    'MSEdgeHTM_.html', 'MSEdgePDF_.pdf', 'MSEdgeHTM_.svg', 'MSEdgeHTM_mailto', 'MSEdgeHTM_read',
    'MSEdgeHTM_.mht', 'MSEdgeMHT_.mht', 'MSEdgeHTM_.mhtml', 'MSEdgeMHT_.mhtml', 'MSEdgeHTM_microsoft-edge'
)
foreach ($assoc in $assocToRemove) {
    Write-Output "Processing: $assoc"
    if (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts") {
        Try {
            Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" -Name $assoc -ErrorAction SilentlyContinue
            Write-Output "Removed association for: $assoc"
        } Catch {
            Write-Output "Failed to remove association for: $assoc - $($_.Exception.Message)"
        }
    } Else {
        Write-Output "Path not found for: $assoc"
    }
}

# Remove Edge Open With associations
Write-Output "--- Removing Open With associations for Edge ---"
$openWithToRemove = @(
    'HKLM:\Software\Classes\.htm\OpenWithProgids\MSEdgeHTM',
    'HKLM:\Software\Classes\.html\OpenWithProgids\MSEdgeHTM',
    'HKLM:\Software\Classes\.mht\OpenWithProgids\MSEdgeMHT',
    'HKLM:\Software\Classes\.mhtml\OpenWithProgids\MSEdgeMHT',
    'HKLM:\Software\Classes\.pdf\OpenWithProgids\MSEdgePDF',
    'HKLM:\Software\Classes\.shtml\OpenWithProgids\MSEdgeHTM',
    'HKLM:\Software\Classes\.svg\OpenWithProgids\MSEdgeHTM',
    'HKLM:\Software\Classes\.webp\OpenWithProgids\MSEdgeHTM',
    'HKLM:\Software\Classes\.xht\OpenWithProgids\MSEdgeHTM',
    'HKLM:\Software\Classes\.xhtml\OpenWithProgids\MSEdgeHTM',
    'HKLM:\Software\Classes\.xml\OpenWithProgids\MSEdgeHTM'
)
foreach ($openWith in $openWithToRemove) {
    Write-Output "Processing: $openWith"
    if (Test-Path $openWith) {
        Try {
            Remove-ItemProperty -Path $openWith -ErrorAction SilentlyContinue
            Write-Output "Removed Open With association for: $openWith"
        } Catch {
            Write-Output "Failed to remove Open With association for: $openWith - $($_.Exception.Message)"
        }
    } Else {
        Write-Output "Path not found for: $openWith"
    }
}

# Remove Edge user associations
Write-Output "--- Removing user associations for Edge ---"
$urlsToRemove = @(
    'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice',
    'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice',
    'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\microsoft-edge\UserChoice',
    'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\microsoft-edge-holographic\UserChoice',
    'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-xbl-3d8b930f\UserChoice',
    'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\read\UserChoice'
)
foreach ($url in $urlsToRemove) {
    Write-Output "Processing: $url"
    if (Test-Path $url) {
        Try {
            Remove-ItemProperty -Path $url -Name 'ProgId' -ErrorAction SilentlyContinue
            Write-Output "Removed user association for: $url"
        } Catch {
            Write-Output "Failed to remove user association for: $url - $($_.Exception.Message)"
        }
    } Else {
        Write-Output "Path not found for: $url"
    }
}

# Remove Edge shortcuts
Write-Output "--- Removing Edge shortcuts ---"
$shortcutsToRemove = @(
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
    "C:\Users\Admin\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk",
    "C:\Users\Admin\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk",
    "C:\Users\Public\Desktop\Microsoft Edge.lnk",
    "C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk",
    "C:\Users\Admin\Desktop\Microsoft Edge.lnk"
)
foreach ($shortcut in $shortcutsToRemove) {
    Write-Output "Processing: $shortcut"
    if (Test-Path $shortcut) {
        Try {
            Remove-Item -Path $shortcut -ErrorAction SilentlyContinue
            Write-Output "Removed shortcut: $shortcut"
        } Catch {
            Write-Output "Failed to remove shortcut: $shortcut - $($_.Exception.Message)"
        }
    } Else {
        Write-Output "Shortcut not found: $shortcut"
    }
}

# Remove Edge through official installer
Write-Output "--- Uninstalling Microsoft Edge ---"
$edgeUninstallerPath = "C:\Program Files (x86)\Microsoft\Edge\Application\135.0.3179.73\Installer\setup.exe"
If (Test-Path $edgeUninstallerPath) {
    Try {
        Start-Process $edgeUninstallerPath -ArgumentList "/uninstall /silent /force" -Wait
        Write-Output "Microsoft Edge uninstalled successfully."
    } Catch {
        Write-Output "Failed to uninstall Microsoft Edge: $($_.Exception.Message)"
    }
} Else {
    Write-Output "Edge uninstaller not found."
}

# Previous operations in your script (existing logic)...

# Add this section at the end for complete cleanup:
Write-Output "--- Starting Complete Edge Cleanup ---"

# Stop any Edge-related processes
Write-Output "Stopping Microsoft Edge-related processes..."
Stop-Process -Name "msedge*" -Force -ErrorAction SilentlyContinue

# Remove Edge installation folders
Write-Output "Removing Microsoft Edge installation folders..."
$foldersToRemove = @(
    "C:\Program Files (x86)\Microsoft\Edge",
    "C:\Program Files\Microsoft\Edge",
    "C:\ProgramData\Microsoft\Edge",
    "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge",
    "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe"
)
foreach ($folder in $foldersToRemove) {
    Write-Output "Processing: $folder"
    if (Test-Path $folder) {
        Try {
            Remove-Item -Path $folder -Recurse -Force
            Write-Output "Removed folder: $folder"
        } Catch {
            Write-Output "Failed to remove folder: $folder - $($_.Exception.Message)"
        }
    } Else {
        Write-Output "Folder not found: $folder"
    }
}

# Remove Edge registry keys
Write-Output "Removing Microsoft Edge-related registry keys..."
$registryKeysToRemove = @(
    "HKLM:\SOFTWARE\Microsoft\EdgeUpdate",
    "HKLM:\SOFTWARE\Microsoft\Edge",
    "HKCU:\SOFTWARE\Microsoft\EdgeUpdate",
    "HKCU:\SOFTWARE\Microsoft\Edge",
    "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe"
)
foreach ($key in $registryKeysToRemove) {
    Write-Output "Processing: $key"
    if (Test-Path $key) {
        Try {
            Remove-Item -Path $key -Recurse -Force
            Write-Output "Removed registry key: $key"
        } Catch {
            Write-Output "Failed to remove registry key: $key - $($_.Exception.Message)"
        }
    } Else {
        Write-Output "Registry key not found: $key"
    }
}

# Clean up leftover shortcuts
Write-Output "Removing leftover Edge shortcuts..."
$shortcutsToRemove = @(
    "C:\Users\$env:USERNAME\Desktop\Microsoft Edge.lnk",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
    "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk",
    "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk",
    "C:\Users\Public\Desktop\Microsoft Edge.lnk"
)
foreach ($shortcut in $shortcutsToRemove) {
    Write-Output "Processing: $shortcut"
    if (Test-Path $shortcut) {
        Try {
            Remove-Item -Path $shortcut -Force
            Write-Output "Removed shortcut: $shortcut"
        } Catch {
            Write-Output "Failed to remove shortcut: $shortcut - $($_.Exception.Message)"
        }
    } Else {
        Write-Output "Shortcut not found: $shortcut"
    }
}

Get-AppxPackage *MicrosoftEdge* | Remove-AppxPackage
Get-AppxPackage *MicrosoftEdgeDevToolsClient* | Remove-AppxPackage

# For system-level removal, you might need to modify permissions
takeown /f "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /r /d y
icacls "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /grant administrators:F /t
Remove-Item -Path "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -Recurse -Force
takeown /f "C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe" /r /d y
icacls "C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe" /grant administrators:F /t
Get-AppxPackage *MicrosoftEdgeDevToolsClient* | Remove-AppxPackage
Remove-Item -Path "C:\Windows\SystemApps\Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe" -Recurse -Force
takeown /f "C:\Program Files (x86)\Microsoft" /r /d y
icacls "C:\Program Files (x86)\Microsoft" /grant administrators:F /t
Remove-Item -Path "C:\Program Files (x86)\Microsoft" -Recurse -Force
# Create the Registry key to block Edge from being reinstalled
$regKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $regKeyPath)) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Edge" -Force
}
New-ItemProperty -Path $regKeyPath -Name "PreventMicrosoftEdgeRollback" -Value 1 -PropertyType DWord -Force
Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\*Microsoft Edge*" -Recurse -Force
Remove-Item -Path "C:\Users\$env:UserName\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*Microsoft Edge*" -Recurse -Force
Remove-Item -Path "C:\Users\$env:UserName\AppData\Local\Microsoft\Edge" -Recurse -Force
Remove-Item -Path "C:\Program Files (x86)\Microsoft\Edge" -Recurse -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PreventMicrosoftEdgeRollback" -Value 1 -Type DWord

# In General Section of Setting
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0 -Type DWord
Set-ItemProperty -Path 'HKCU:\Control Panel\International\User Profile' -Name 'HttpAcceptLanguageOptOut' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackProgs' -Value 0 -Type DWord
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'SubscribedContent-338389Enabled' -Value 0 -Type DWord

# Cortana 
# Define the hosts file path
$hostsFilePath = "$env:SYSTEMROOT\System32\drivers\etc\hosts"
$hostsFileEncoding = [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Utf8

# List of domains to block
$domains = @(
    "business.bing.com", "c.bing.com", "th.bing.com", "edgeassetservice.azureedge.net",
    "c-ring.msedge.net", "fp.msedge.net", "I-ring.msedge.net", "s-ring.msedge.net",
    "dual-s-ring.msedge.net", "creativecdn.com", "a-ring-fallback.msedge.net",
    "fp-afd-nocache-ccp.azureedge.net", "prod-azurecdn-akamai-iris.azureedge.net",
    "widgetcdn.azureedge.net", "widgetservice.azurefd.net", "fp-vs.azureedge.net",
    "ln-ring.msedge.net", "t-ring.msedge.net", "t-ring-fdv2.msedge.net", "tse1.mm.bing.net"
)

# Define blocking IPs
$blockingHostsEntries = @(@{ AddressType = "IPv4"; IPAddress = '0.0.0.0' }, @{ AddressType = "IPv6"; IPAddress = '::1' })

# Ensure hosts file exists
if (!(Test-Path $hostsFilePath)) {
    Write-Output "Creating a new hosts file at $hostsFilePath."
    try {
        New-Item -Path $hostsFilePath -ItemType File -Force -ErrorAction Stop | Out-Null
        Write-Output "Successfully created the hosts file."
    } catch {
        Write-Error "Failed to create the hosts file. Error: $_"
        exit 1
    }
}

# Iterate over domains and add blocking entries
foreach ($domain in $domains) {
    foreach ($blockingEntry in $blockingHostsEntries) {
        Write-Output "Processing addition for $($blockingEntry.AddressType) entry for $domain."
        try {
            $hostsFileContents = Get-Content -Path $hostsFilePath -Raw -Encoding $hostsFileEncoding -ErrorAction Stop
        } catch {
            Write-Error "Failed to read the hosts file. Error: $_"
            continue
        }
        
        $hostsEntryLine = "$($blockingEntry.IPAddress)`t$domain # $comment"
        if ($hostsFileContents -match [regex]::Escape($hostsEntryLine)) {
            Write-Output "Skipping $domain, entry already exists."
            continue
        }

        try {
            Add-Content -Path $hostsFilePath -Value $hostsEntryLine -Encoding $hostsFileEncoding -ErrorAction Stop
            Write-Output "Successfully added $domain entry."
        } catch {
            Write-Error "Failed to add $domain entry. Error: $_"
            continue
        }
    }
}

# Disable Cortana via Registry
$registryChanges = @(
    @{ Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="CortanaConsent"; Value=0 },
    @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowCortana"; Value=0 },
    @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowCloudSearch"; Value=0 },
    @{ Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"; Name="CortanaEnabled"; Value=0 }
)

foreach ($change in $registryChanges) {
    Set-ItemProperty -Path $change.Path -Name $change.Name -Value $change.Value
}

# Disable Cortana Scheduled Tasks
$tasks = @("\Microsoft\Windows\Search\Cortana", "\Microsoft\Windows\Cortana\CortanaBackgroundTask", "\Microsoft\Windows\Cortana\CortanaUI")
foreach ($task in $tasks) {
    schtasks /Delete /TN $task /F
    Write-Host "Deleted Cortana scheduled task: $task" -ForegroundColor Green
}

# Stop and disable Cortana Services
Set-Service -Name "CDPUserSvc" -StartupType Disabled
Stop-Service -Name "CDPUserSvc" -Force
Set-Service -Name "WSearch" -StartupType Disabled
Stop-Service -Name "WSearch" -Force
Write-Host "Disabled Windows Search service." -ForegroundColor Green

# Uninstall Cortana
Get-AppxPackage -AllUsers | Where-Object {$_.Name -match "Cortana"} | Remove-AppxPackage -AllUsers

# Block Cortana Executable
$searchUIPath = "$env:SystemRoot\SystemApps\Microsoft.Windows.Cortana*"
if (Test-Path $searchUIPath) {
    Rename-Item -Path $searchUIPath -NewName "$searchUIPath.Blocked" -Force
    Write-Host "Blocked Cortana's executable." -ForegroundColor Green
}

# Prevent Cortana from loading
$searchFolder = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.Cortana*"
if (Test-Path $searchFolder) {
    icacls $searchFolder /deny Everyone:(OI)(CI)F
    Write-Host "Blocked access to Cortana package folder." -ForegroundColor Green
}

# To remove Narrator
takeown /f C:\Windows\System32\Narrator.exe
icacls C:\Windows\System32\Narrator.exe /grant administrators:F
Rename-Item -Path "C:\Windows\System32\Narrator.exe" -NewName "Narrator_DISABLED.exe" -Force

### STEP 1: Disable Narrator via Registry
$registryKeys = @(
    "HKCU:\Software\Microsoft\Narrator",
    "HKLM:\SOFTWARE\Microsoft\Narrator",
    "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Accessibility",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility"
)

$registryValues = @{
    "ScreenReaderRunning" = 0
    "WinEnterLaunchEnabled" = 0
    "NarratorEnabled" = 0
    "Configuration" = ""
}

foreach ($key in $registryKeys) {
    if (-not (Test-Path $key)) {
        New-Item -Path $key -Force
    }
    foreach ($name in $registryValues.Keys) {
        Set-ItemProperty -Path $key -Name $name -Value $registryValues[$name] -Type DWord -Force
        Write-Host "Disabled $name in $key"
    }
}

### STEP 2: Disable Narrator Services
$services = @("Narrator")
foreach ($service in $services) {
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    Set-Service -Name $service -StartupType Disabled
    Write-Host "Disabled service: $service"
}

### STEP 3: Disable Narrator Keyboard Shortcuts
Write-Host "Disabling Narrator keyboard shortcuts..."
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility"
Set-ItemProperty -Path $regPath -Name "Configuration" -Value "" -Type String -Force

### STEP 4: Remove Narrator from Startup
$startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$startupNarrator = Get-Item "$startupFolder\Narrator.lnk" -ErrorAction SilentlyContinue

if ($startupNarrator) {
    Remove-Item "$startupFolder\Narrator.lnk" -Force
    Write-Host "Removed Narrator from Startup."
}

### STEP 5: Block Narrator Executable
$exePaths = @(
    "C:\Windows\System32\Narrator.exe",
    "C:\Windows\SysWOW64\Narrator.exe"
)

foreach ($exePath in $exePaths) {
    if (Test-Path $exePath) {
        Rename-Item -Path $exePath -NewName "$exePath.DISABLED" -Force
        Write-Host "Blocked Narrator executable: $exePath"
    }
}

### STEP 6: Remove Narrator-related Scheduled Tasks
$scheduledTasks = @(
    "\Microsoft\Windows\Accessibility\EnableNarrator"
)

foreach ($task in $scheduledTasks) {
    schtasks /Change /TN $task /Disable
    Write-Host "Disabled Scheduled Task: $task"
}

# Meet Now
schtasks /Delete /TN "\Microsoft\Windows\MeetNow\MeetNowTask" /F

# Function to Set Registry Keys
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWORD"
    )

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
    Write-Host "Updated: $Path\$Name -> $Value" -ForegroundColor Green
}

# Advanced Registry Edits to Hide and Block Meet Now
$registryChanges = @(
    @{Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="HideSCAMeetNow"; Value=1},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="HideSCAMeetNow"; Value=1},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name="ExcludeWUDriversInQualityUpdate"; Value=1},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="DisableMeetNow"; Value=1},
    @{Path="HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="DisableMeetNow"; Value=1}
)

foreach ($change in $registryChanges) {
    Set-RegistryValue -Path $change.Path -Name $change.Name -Value $change.Value
}

# Disable and Remove Meet Now App via Windows Components
Write-Output "--- Removing Meet Now App ---"
Get-AppxPackage -AllUsers | Where-Object {$_.Name -match "MeetNow"} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Write-Host "Meet Now app removed." -ForegroundColor Green

# Block Meet Now via Group Policy
$gpRegistryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
)

foreach ($gpPath in $gpRegistryPaths) {
    if (!(Test-Path $gpPath)) { New-Item -Path $gpPath -Force }
    Set-ItemProperty -Path $gpPath -Name "NoMeetNow" -Value 1
}
Write-Host "Meet Now permanently blocked via Group Policy." -ForegroundColor Green

# Stop and Disable Meet Now Service
Set-Service -Name "MeetNowService" -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service -Name "MeetNowService" -Force -ErrorAction SilentlyContinue
Write-Host "Meet Now service disabled." -ForegroundColor Green

# Delete Meet Now Scheduled Task if it exists
$tasks = @("\Microsoft\Windows\MeetNow\MeetNowTask")
foreach ($task in $tasks) {
    schtasks /Delete /TN $task /F -ErrorAction SilentlyContinue
    Write-Host "Deleted Meet Now scheduled task: $task" -ForegroundColor Green
}

# Check if MeetNow.exe still exists and block execution
$meetNowExePath = "$env:SystemRoot\System32\MeetNow.exe"
if (Test-Path $meetNowExePath) {
    icacls $meetNowExePath /deny Everyone:F
    Write-Host "Blocked MeetNow.exe execution permanently." -ForegroundColor Green
}

# This script removes all Start Menu Tiles from the .default user #

Set-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -Value '<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <LayoutOptions StartTileGroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:StartLayout GroupCellWidth="6" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </StartLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  </DefaultLayoutOverride>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        <taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:UWA AppUserModelID="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        </taskbar:TaskbarPinList>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      </defaultlayout:TaskbarLayout>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </CustomTaskbarLayoutCollection>'
Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '</LayoutModificationTemplate>'

$START_MENU_LAYOUT = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

$layoutFile="C:\Windows\StartMenuLayout.xml"

#Delete layout file if it already exists
If(Test-Path $layoutFile)
{
    Remove-Item $layoutFile
}

#Creates the blank layout file
$START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

$regAliases = @("HKLM", "HKCU")

#Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    IF(!(Test-Path -Path $keyPath)) { 
        New-Item -Path $basePath -Name "Explorer"
    }
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
    Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
}

#Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
Stop-Process -name explorer
Start-Sleep -s 5
$wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
Start-Sleep -s 5

#Enable the ability to pin items again by disabling "LockedStartLayout"
foreach ($regAlias in $regAliases){
    $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
    $keyPath = $basePath + "\Explorer" 
    Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0
}

#Restart Explorer and delete the layout file
Stop-Process -name explorer

# Uncomment the next line to make clean start menu default for all new users
Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\

Remove-Item $layoutFile

Pause
