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

# --- 1. MASTER FUNCTION: Set-ServiceState ---
# This must be at the top of your script. It handles wildcards (like _52b91)
# and uses standard Windows commands to ensure system stability.
function Set-ServiceState {
    param (
        [string[]]$ServiceList,
        [string]$State # "Disable" or "Manual" or "Automatic"
    )
    foreach ($name in $ServiceList) {
        # The asterisk (*) ensures we catch per-user services automatically
        $services = Get-Service -Name "$name*" -ErrorAction SilentlyContinue
        foreach ($svc in $services) {
            try {
                if ($State -eq "Disable") {
                    Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-Host "[X] Disabled: $($svc.Name)" -ForegroundColor Gray
                } elseif ($State -eq "Manual") {
                    Set-Service -Name $svc.Name -StartupType Manual -ErrorAction SilentlyContinue
                    Write-Host "[!] Set to Manual: $($svc.Name)" -ForegroundColor Green
                } elseif ($State -eq "Automatic") {
                    Set-Service -Name $svc.Name -StartupType Automatic -ErrorAction SilentlyContinue
                    Write-Host "[!] Set to Automatic: $($svc.Name)" -ForegroundColor Cyan
                }
            } catch {
                Write-Host "[i] Skipping: $($svc.Name) (Protected Core Service)" -ForegroundColor Yellow
            }
        }
    }
}
Clear-Host
Write-Host "--- Windows Service Optimization: High Performance / Zero Break ---" -ForegroundColor White
Write-Host "Action: Standard Disable | Profile: Ultra-Lean" -ForegroundColor Cyan
Write-Host "------------------------------------------------------------"


Clear-Host
Write-Host "--- Windows Service Optimization Script ---" -ForegroundColor White
Write-Host "Profile: No Games | No Printers | No Remote Access" -ForegroundColor Yellow
Write-Host "------------------------------------------------------------"


# 1. ALWAYS DISABLE (Your custom 'Ultra-Lean' List)
$bloat = @(
    # --- Gaming & Xbox (No Gaming) ---
    "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc",  "GamingServices", "GamingServicesNet",
    
    # --- Microsoft Edge (Uninstalled) ---
    "edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService",
    
    # --- Telemetry, Diagnostics & Beta Testing ---
    "DiagTrack", "WerSvc", "dmwappushservice", "diagsvc", "wisvc", "DPS", "WdiServiceHost", "WdiSystemHost", 
    "WSearch", "AxInstSV",
    
    # --- Identity & Payments (No Payments/Smart Cards) ---
    "WalletService", "SEMgrSvc", "EntAppStoreSvc", "SCardSvr", "ScDeviceEnum", "SCPolicySvc", "WpcMonSvc",
    
    # --- Backup & Shadow Copies (No Backup) ---
    "fhsvc", "SDRSVC", "VSS", "wbengine",
    
    # --- General Bloat ---
    "MapsBroker", "Fax", "PhoneSvc", "RetailDemo", "workfolderssvc", "AssignedAccessManagerSvc", 
    "SensorService", "SensorDataService", "SensrSvc", "TrkWks", 
    
    # --- Virtualization (Hyper-V) ---
    "HvHost", "vmickvpexchange", "vmicguestinterface", "vmicshutdown", "vmicheartbeat", 
    "vmicvmsession", "vmicrdv", "vmictimesync", "vmicvss"
)

Write-Host "[*] Disabling confirmed background bloat..." -ForegroundColor Cyan
Set-ServiceState -ServiceList $bloat -State "Disable"
# --- 2. REMOTE DESKTOP ---
$RDPChoice = Read-Host "`nDo you use Remote Desktop (Control this PC from another device)? (Y/N)"
if ($RDPChoice -ne "Y") {
    Write-Host "[i] Disabling Remote Desktop Services..." -ForegroundColor Yellow
    Set-ServiceState -ServiceList @("TermService", "SessionEnv", "UmRdpService", "RemoteRegistry") -State "Disable"
} else {
    Write-Host "[i] Enabling Remote Desktop Services..." -ForegroundColor Green
    Set-ServiceState -ServiceList @("TermService", "SessionEnv", "UmRdpService") -State "Manual"
}
# --- 3. PRINTERS ---
$PrinterChoice = Read-Host "Do you use a Printer? (Y/N)"
if ($PrinterChoice -eq "Y") {
    Write-Host "[i] Enabling Printer services..." -ForegroundColor Green
    # Spooler is set to Automatic so the printer is ready as soon as you boot
    Set-ServiceState -ServiceList @("Spooler") -State "Automatic"
    Set-ServiceState -ServiceList @("PrintNotify") -State "Manual"
    Start-Service -Name "Spooler" -ErrorAction SilentlyContinue
} else {
    Write-Host "[i] Disabling Printer services..." -ForegroundColor Yellow
    Set-ServiceState -ServiceList @("Spooler", "PrintNotify") -State "Disable"
}

# --- 4. TOUCH & BIOMETRICS ---
$TouchChoice = Read-Host "`nDo you use a Touch Screen, Stylus, or Face/Fingerprint login? (Y/N)"
if ($TouchChoice -eq "Y") {
    Write-Host "[i] Enabling Touch/Biometric Services..." -ForegroundColor Green
    # We use Automatic for Biometrics to ensure Windows Hello is ready at the Login Screen
    Set-ServiceState -ServiceList @("TabletInputService", "WbioSrvc") -State "Automatic"
    Start-Service -Name "WbioSrvc" -ErrorAction SilentlyContinue
} else {
    Write-Host "[i] Disabling Touch/Biometric Services..." -ForegroundColor Yellow
    Set-ServiceState -ServiceList @("TabletInputService", "WbioSrvc") -State "Disable"
}

# --- 5. BLUETOOTH ---
$BthChoice = Read-Host "`nDo you use Bluetooth (Mouse/Headphones)? (Y/N)"
if ($BthChoice -eq "Y") {
    Write-Host "[i] Enabling Bluetooth Services..." -ForegroundColor Green
    # We use Manual so they only run when a device tries to connect
    Set-ServiceState -ServiceList @("bthserv", "BTAGService", "BthAvctpSvc", "BluetoothUserService") -State "Manual"
} else {
    Write-Host "[i] Disabling Bluetooth Services..." -ForegroundColor Yellow
    Set-ServiceState -ServiceList @("bthserv", "BTAGService", "BthAvctpSvc", "BluetoothUserService") -State "Disable"
}

# --- 6. APPS & STORE (Optimized for Calculator/Photos) ---
# Setting these to Manual ensures they use 0% CPU/RAM until you open an app.
Write-Host "`n[i] Configuring Store & License services for App support..." -ForegroundColor Cyan

$StoreServices = @("AppXSvc", "StoreSvc", "ClipSVC", "LicenseManager")

# Using the function ensures standard behavior across all Windows versions
Set-ServiceState -ServiceList $StoreServices -State "Manual"

Write-Host "SUCCESS: Store apps (Calculator/Photos) will work on-demand." -ForegroundColor Green

# --- 7. WINDOWS UPDATE ---
$UpdateChoice = Read-Host "`nKeep Windows Update enabled? (Y/N)"
$UpdateServices = @("wuauserv", "UsoSvc", "BITS", "WaaSMedicSvc")

if ($UpdateChoice -eq "Y") {
    Write-Host "[i] Setting Update Services to Manual..." -ForegroundColor Green
    # Manual is "Perfect" because it doesn't waste RAM, but works when you click "Check for Updates"
    Set-ServiceState -ServiceList $UpdateServices -State "Manual"
} else {
    Write-Host "[i] Disabling Windows Update Services..." -ForegroundColor Yellow
    Set-ServiceState -ServiceList $UpdateServices -State "Disable"
}

# --- 8. BITLOCKER ---
$BitLockerChoice = Read-Host "`nDo you use BitLocker Drive Encryption? (Y/N)"
if ($BitLockerChoice -ne "Y") {
    # Check if any drive is actually encrypted before disabling
    $EncryptionStatus = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.VolumeStatus -eq 'Encrypted' }
    
    if ($EncryptionStatus) {
        Write-Host "[!] WARNING: Detected encrypted drives. Skipping disable to prevent lockout." -ForegroundColor Red
    } else {
        Write-Host "[i] Disabling BitLocker services..." -ForegroundColor Yellow
        Set-ServiceState -ServiceList @("BDESVC") -State "Disable"
    }
} else {
    Write-Host "[i] Keeping BitLocker enabled (Manual)..." -ForegroundColor Green
    Set-ServiceState -ServiceList @("BDESVC") -State "Manual"
}

# --- 9. SYSMAIN (SUPERFETCH) ---
$DriveType = Read-Host "`nAre you using an SSD as your primary drive? (Y/N)"

if ($DriveType -eq "Y") {
    Write-Host "[i] SSD detected. Disabling SysMain..." -ForegroundColor Yellow
    # Stopping the service first, then disabling it
    Stop-Service -Name "SysMain" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "SysMain" -StartupType Disabled
} else {
    Write-Host "[i] HDD detected. Setting SysMain to Automatic..." -ForegroundColor Green
    # Setting to Automatic ensures it starts on every boot
    Set-Service -Name "SysMain" -StartupType Automatic
    Start-Service -Name "SysMain" -ErrorAction SilentlyContinue
}

$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"

Write-Host "`n--- Camera & Microphone Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE Camera & Microphone? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Unlocking Hardware Access..." -ForegroundColor Gray
    
    # Remove Policy Restrictions
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessCamera" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessMicrophone" -ErrorAction SilentlyContinue
    }

    # Set Consent to Allow
    foreach ($dev in @("webcam", "microphone")) {
        $fullPath = "$consentPath\$dev"
        if (-not (Test-Path $fullPath)) { New-Item -Path $fullPath -Force | Out-Null }
        Set-ItemProperty -Path $fullPath -Name "Value" -Value "Allow" -ErrorAction SilentlyContinue
    }
    Write-Host "SUCCESS: Devices are ENABLED and control is restored to Settings." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Hardware Access..." -ForegroundColor Gray

    # Apply Policy Force Deny (Value 2)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessCamera" -Value 2 -Type DWord
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessMicrophone" -Value 2 -Type DWord
    
    # Set Consent to Deny
    foreach ($dev in @("webcam", "microphone")) {
        $fullPath = "$consentPath\$dev"
        if (-not (Test-Path $fullPath)) { New-Item -Path $fullPath -Force | Out-Null }
        Set-ItemProperty -Path $fullPath -Name "Value" -Value "Deny" -ErrorAction SilentlyContinue
    }
    Write-Host "SUCCESS: Devices are LOCKED. No apps can access Camera or Mic." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}
Write-Host "`nDone." -ForegroundColor Cyan

# Your original logic starts here...
$choice = Read-Host "Do you want to enable Voice Activation? (Y/N)"
$appPrivacyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$voiceSettingsPath = "HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps"

if ($choice -eq "Y") {
    Write-Host "--- Enabling Voice Activation ---" -ForegroundColor Green
    $policyNames = @('LetAppsActivateWithVoice', 'LetAppsActivateWithVoiceAboveLock')
    foreach ($name in $policyNames) {
        Remove-ItemProperty -Path $appPrivacyPath -Name $name -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path $voiceSettingsPath)) { New-Item -Path $voiceSettingsPath -Force | Out-Null }
    Set-ItemProperty -Path $voiceSettingsPath -Name "AgentActivationEnabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $voiceSettingsPath -Name "AgentActivationOnLockScreenEnabled" -Value 1 -Type DWord
    Write-Host "SUCCESS: Settings restored."
}
elseif ($choice -eq "N") {
    Write-Host "--- Disabling Voice Activation ---" -ForegroundColor Yellow
    if (-not (Test-Path $appPrivacyPath)) { New-Item -Path $appPrivacyPath -Force | Out-Null }
    Set-ItemProperty -Path $appPrivacyPath -Name "LetAppsActivateWithVoice" -Value 2 -Type DWord
    Set-ItemProperty -Path $appPrivacyPath -Name "LetAppsActivateWithVoiceAboveLock" -Value 2 -Type DWord

    if (-not (Test-Path $voiceSettingsPath)) { New-Item -Path $voiceSettingsPath -Force | Out-Null }
    Set-ItemProperty -Path $voiceSettingsPath -Name "AgentActivationEnabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $voiceSettingsPath -Name "AgentActivationOnLockScreenEnabled" -Value 0 -Type DWord
    Write-Host "SUCCESS: Voice Activation safely locked."
}

$notifChoice = Read-Host "Do you want App Notifications? (Y/N)"

# Paths
$toastPath  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications"
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$notifPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener"
$guidPath   = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}"

if ($notifChoice -eq "Y") {
    Write-Host "--- Enabling App Notifications (Restoring Control) ---" -ForegroundColor Green

    # 1. Enable Toasts
    if (-not (Test-Path $toastPath)) { New-Item -Path $toastPath -Force | Out-Null }
    Set-ItemProperty -Path $toastPath -Name "ToastEnabled" -Value 1 -Type DWord

    # 2. Clear Policy Restrictions
    Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessNotifications" -ErrorAction SilentlyContinue
    
    # 3. Allow ConsentStore
    if (-not (Test-Path $notifPath)) { New-Item -Path $notifPath -Force | Out-Null }
    Set-ItemProperty -Path $notifPath -Name "Value" -Value "Allow" -Type String

    # 4. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Notifications enabled." -ForegroundColor Green
}
elseif ($notifChoice -eq "N") {
    Write-Host "--- Disabling App Notifications (Hard Lock) ---" -ForegroundColor Yellow

    # 1. Disable Toasts
    if (-not (Test-Path $toastPath)) { New-Item -Path $toastPath -Force | Out-Null }
    Set-ItemProperty -Path $toastPath -Name "ToastEnabled" -Value 0 -Type DWord

    # 2. Apply Policy Lock (Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessNotifications" -Value 2 -Type DWord

    # 3. Deny ConsentStore
    if (-not (Test-Path $notifPath)) { New-Item -Path $notifPath -Force | Out-Null }
    Set-ItemProperty -Path $notifPath -Name "Value" -Value "Deny" -Type String

    # 4. Deny Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny" -Type String

    Write-Host "SUCCESS: Notifications fully disabled and locked." -ForegroundColor Yellow
}

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
$lfsvcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc"
$guidBase = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global"
$guids = @("{BFA794E4-F964-4FDB-90F6-51056BFE4B44}", "{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}")

Write-Host "`n--- Windows Location Services Master Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE Location Services? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring Location Services and User Control..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessLocation" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Enable Geolocation Service
    Set-ItemProperty -Path "$lfsvcPath\Service\Configuration" -Name "Status" -Value 1 -ErrorAction SilentlyContinue
    Set-Service -Name "lfsvc" -StartupType Manual
    Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue

    # 4. Clear Legacy GUIDs
    foreach ($guid in $guids) {
        Remove-ItemProperty -Path "$guidBase\$guid" -Name "Value" -ErrorAction SilentlyContinue
    }

    Write-Host "SUCCESS: Location services are ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking All Location Services..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessLocation" -Value 2 -Type DWord
    
    # Clear white-lists
    $nullLists = @("LetAppsAccessLocation_UserInControlOfTheseApps", "LetAppsAccessLocation_ForceAllowTheseApps", "LetAppsAccessLocation_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Kill and Disable Geolocation Service
    Stop-Service -Name "lfsvc" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "lfsvc" -StartupType Disabled
    if (-not (Test-Path "$lfsvcPath\Service\Configuration")) { New-Item -Path "$lfsvcPath\Service\Configuration" -Force | Out-Null }
    Set-ItemProperty -Path "$lfsvcPath\Service\Configuration" -Name "Status" -Value 0 -Type DWord

    # 4. Hard-Lock Legacy GUIDs
    foreach ($guid in $guids) {
        $path = "$guidBase\$guid"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "Value" -Value "Deny" -Type String
    }

    Write-Host "SUCCESS: Location services are fully KILLED and LOCKED." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}"

Write-Host "`n--- Account Info (Name, Picture, Email) Master Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Access to your Account Info? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring User Control over Account Info..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessAccountInfo" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Account Info access is now ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Account Info Access..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessAccountInfo" -Value 2 -Type DWord
    
    # Clear force-allow/deny lists to prevent individual app overrides
    $nullLists = @("LetAppsAccessAccountInfo_UserInControlOfTheseApps", "LetAppsAccessAccountInfo_ForceAllowTheseApps", "LetAppsAccessAccountInfo_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent Store to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Account Info is now LOCKED and Hidden." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan


# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}"

Write-Host "`n--- Contacts Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Access to your Contacts? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring User Control over Contacts..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessContacts" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Contacts access is now ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Contacts Access..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessContacts" -Value 2 -Type DWord
    
    # Clear force-allow/deny lists to ensure no individual app overrides exist
    $nullLists = @("LetAppsAccessContacts_UserInControlOfTheseApps", "LetAppsAccessContacts_ForceAllowTheseApps", "LetAppsAccessContacts_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent Store to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Contacts are now LOCKED and Hidden." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}"

Write-Host "`n--- Calendar & Appointments Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Access to your Calendar? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring User Control over Calendar..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessCalendar" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Calendar access is now ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Calendar Access..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessCalendar" -Value 2 -Type DWord
    
    # Clear force-allow/deny lists to ensure no individual app overrides exist
    $nullLists = @("LetAppsAccessCalendar_UserInControlOfTheseApps", "LetAppsAccessCalendar_ForceAllowTheseApps", "LetAppsAccessCalendar_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent Store to Deny (Internal name: appointments)
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Your Calendar is now LOCKED and Hidden from apps." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{660ADFCB-443E-449D-99C2-BA74066E99E1}"

Write-Host "`n--- Phone Calls Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Access to Phone Calls? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring User Control over Phone Calls..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessPhone" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Phone Call access is now ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Phone Call Access..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessPhone" -Value 2 -Type DWord
    
    # Clear force-allow/deny lists to ensure no individual app overrides exist
    $nullLists = @("LetAppsAccessPhone_UserInControlOfTheseApps", "LetAppsAccessPhone_ForceAllowTheseApps", "LetAppsAccessPhone_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent Store to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Phone Call management is now LOCKED." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan
# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}"

Write-Host "`n--- Call History Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Access to Call History? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring User Control over Call History..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessCallHistory" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Call History access is now ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Call History Access..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessCallHistory" -Value 2 -Type DWord
    
    # Clear force-allow/deny lists to prevent individual app overrides
    $nullLists = @("LetAppsAccessCallHistory_UserInControlOfTheseApps", "LetAppsAccessCallHistory_ForceAllowTheseApps", "LetAppsAccessCallHistory_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent Store to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Call History is now LOCKED and Hidden." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}"

Write-Host "`n--- Windows Email Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Access to Windows Email? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring User Control over Email Access..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessEmail" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Email access is now ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Email Access..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessEmail" -Value 2 -Type DWord
    
    # Clear force-allow/deny lists to prevent individual app overrides
    $nullLists = @("LetAppsAccessEmail_UserInControlOfTheseApps", "LetAppsAccessEmail_ForceAllowTheseApps", "LetAppsAccessEmail_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent Store to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Windows Email is now LOCKED and Shielded." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan


# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}"

Write-Host "`n--- Tasks & Reminders Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Access to your Tasks? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring User Control over Tasks..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessTasks" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Tasks access is now ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Tasks Access..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessTasks" -Value 2 -Type DWord
    
    # Clear force-allow/deny lists to ensure no individual app overrides exist
    $nullLists = @("LetAppsAccessTasks_UserInControlOfTheseApps", "LetAppsAccessTasks_ForceAllowTheseApps", "LetAppsAccessTasks_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent Store to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Your Tasks are now LOCKED and Hidden from apps." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
$guidBase = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global"
$guids = @("{992AFA70-6F47-4148-B3E9-3003349C1548}", "{21157C1F-2651-4CC1-90CA-1F28B02263F6}")

Write-Host "`n--- Messaging (SMS/MMS) Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE Messaging Access? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Unlocking Messaging Access..." -ForegroundColor Gray
    
    # 1. Remove Policy Restrictions (Master Lock)
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessMessaging" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent Store to Allow
    $chatPath = "$consentPath\chat"
    if (-not (Test-Path $chatPath)) { New-Item -Path $chatPath -Force | Out-Null }
    Set-ItemProperty -Path $chatPath -Name "Value" -Value "Allow" -ErrorAction SilentlyContinue

    # 3. Clean up Legacy GUIDs
    foreach ($guid in $guids) {
        Remove-ItemProperty -Path "$guidBase\$guid" -Name "Value" -ErrorAction SilentlyContinue
    }

    Write-Host "SUCCESS: Messaging access is ENABLED and restored to your control." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Messaging Access..." -ForegroundColor Gray

    # 1. Apply Policy Force Deny (Value 2)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessMessaging" -Value 2 -Type DWord
    
    # Clear whitelist/blacklist strings
    $nullLists = @("LetAppsAccessMessaging_UserInControlOfTheseApps", "LetAppsAccessMessaging_ForceAllowTheseApps", "LetAppsAccessMessaging_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent Store to Deny
    $chatPath = "$consentPath\chat"
    if (-not (Test-Path $chatPath)) { New-Item -Path $chatPath -Force | Out-Null }
    Set-ItemProperty -Path $chatPath -Name "Value" -Value "Deny" -ErrorAction SilentlyContinue

    # 3. Hard-Lock Legacy GUIDs
    foreach ($guid in $guids) {
        $fullGuidPath = "$guidBase\$guid"
        if (-not (Test-Path $fullGuidPath)) { New-Item -Path $fullGuidPath -Force | Out-Null }
        Set-ItemProperty -Path $fullGuidPath -Name "Value" -Value "Deny" -ErrorAction SilentlyContinue
    }

    Write-Host "SUCCESS: Messaging is LOCKED. No apps can read or send SMS/MMS." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}"

Write-Host "`n--- Radios (Bluetooth/Cellular Control) Master Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Control over Radios? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring User Control over Radios..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessRadios" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Radio control is ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking App Control over Radios..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessRadios" -Value 2 -Type DWord
    
    # Clear white-lists
    $nullLists = @("LetAppsAccessRadios_UserInControlOfTheseApps", "LetAppsAccessRadios_ForceAllowTheseApps", "LetAppsAccessRadios_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Radio control is LOCKED." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$looselyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled"

Write-Host "`n--- Device Communication (Trusted & Unpaired) Master Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE communication with Trusted/Unpaired devices? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring Device Communication Access..." -ForegroundColor Gray
    
    # Remove GPO Locks
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessTrustedDevices" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $policyPath -Name "LetAppsSyncWithDevices" -ErrorAction SilentlyContinue
    }

    # Clear LooselyCoupled Deny
    Remove-ItemProperty -Path $looselyPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Device communication is ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Device Communication..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    
    $policies = @("LetAppsAccessTrustedDevices", "LetAppsSyncWithDevices")
    foreach ($pol in $policies) {
        Set-ItemProperty -Path $policyPath -Name $pol -Value 2 -Type DWord
        
        # Clear white-lists for each policy
        Set-ItemProperty -Path $policyPath -Name "$($pol)_UserInControlOfTheseApps" -Value $null -Type MultiString -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $policyPath -Name "$($pol)_ForceAllowTheseApps" -Value $null -Type MultiString -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $policyPath -Name "$($pol)_ForceDenyTheseApps" -Value $null -Type MultiString -ErrorAction SilentlyContinue
    }

    # 2. Set LooselyCoupled to Deny (Legacy Interface)
    if (-not (Test-Path $looselyPath)) { New-Item -Path $looselyPath -Force | Out-Null }
    Set-ItemProperty -Path $looselyPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Trusted and Unpaired device communication is LOCKED." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$userPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"

Write-Host "`n--- Background Apps Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE Background Apps? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring User Control over Background Apps..." -ForegroundColor Gray
    
    # Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsRunInBackground" -ErrorAction SilentlyContinue
    }

    # Set User Preference to ON (GlobalUserDisabled = 0)
    if (-not (Test-Path $userPath)) { New-Item -Path $userPath -Force | Out-Null }
    Set-ItemProperty -Path $userPath -Name "GlobalUserDisabled" -Value 0 -Type DWord

    Write-Host "SUCCESS: Background Apps are ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Background Apps..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsRunInBackground" -Value 2 -Type DWord
    
    # Clear white-lists (Force Deny ignores these, but it's good practice)
    $nullLists = @("LetAppsRunInBackground_UserInControlOfTheseApps", "LetAppsRunInBackground_ForceAllowTheseApps", "LetAppsRunInBackground_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set User Preference to OFF (GlobalUserDisabled = 1)
    if (-not (Test-Path $userPath)) { New-Item -Path $userPath -Force | Out-Null }
    Set-ItemProperty -Path $userPath -Name "GlobalUserDisabled" -Value 1 -Type DWord

    Write-Host "SUCCESS: All Background Apps are LOCKED and DISABLED." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}"

Write-Host "`n--- App Diagnostics (Information About Other Apps) Master Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Diagnostics access? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring Access to App Information..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsGetDiagnosticInfo" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: App Diagnostics are now ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking App Diagnostics..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsGetDiagnosticInfo" -Value 2 -Type DWord
    
    # Clear white-lists to prevent any specific app from bypassing the block
    $nullLists = @("LetAppsGetDiagnosticInfo_UserInControlOfTheseApps", "LetAppsGetDiagnosticInfo_ForceAllowTheseApps", "LetAppsGetDiagnosticInfo_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: App Diagnostics are now LOCKED." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{245C8541-6143-4041-A474-9A697EB5A647}"

Write-Host "`n--- Documents Library Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Access to your Documents? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring Access to Documents Library..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessDocuments" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Access to Documents is now ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Documents Access..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessDocuments" -Value 2 -Type DWord
    
    # Clear force-allow/deny lists
    $nullLists = @("LetAppsAccessDocuments_UserInControlOfTheseApps", "LetAppsAccessDocuments_ForceAllowTheseApps", "LetAppsAccessDocuments_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent Store to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Access to Documents is now LOCKED." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{EE30207D-9D65-49D6-BE33-E3099F340297}"

Write-Host "`n--- Pictures Library Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Access to your Pictures? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring Access to Pictures Library..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessPictures" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Access to Pictures is now ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Pictures Access..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessPictures" -Value 2 -Type DWord
    
    # Clear force-allow/deny lists
    $nullLists = @("LetAppsAccessPictures_UserInControlOfTheseApps", "LetAppsAccessPictures_ForceAllowTheseApps", "LetAppsAccessPictures_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent Store to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Access to Pictures is now LOCKED." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# --- Paths ---
$policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$consentPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary"
$guidPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{40505828-BA30-4AD3-AF9E-740A8300995F}"

Write-Host "`n--- Videos Library Master Privacy Toggle ---" -ForegroundColor Cyan
$choice = Read-Host "Do you want to ENABLE App Access to your Videos? (Y/N)"

if ($choice -eq "Y") {
    Write-Host "`n[i] Restoring Access to Videos Library..." -ForegroundColor Gray
    
    # 1. Remove GPO Lock
    if (Test-Path $policyPath) {
        Remove-ItemProperty -Path $policyPath -Name "LetAppsAccessVideos" -ErrorAction SilentlyContinue
    }

    # 2. Set Consent to Allow
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Allow"

    # 3. Clear Legacy GUID
    Remove-ItemProperty -Path $guidPath -Name "Value" -ErrorAction SilentlyContinue

    Write-Host "SUCCESS: Access to Videos is now ENABLED." -ForegroundColor Green
}
elseif ($choice -eq "N") {
    Write-Host "`n[i] Hard-Locking Videos Access..." -ForegroundColor Gray

    # 1. Apply Policy Lock (Value 2 = Force Deny)
    if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
    Set-ItemProperty -Path $policyPath -Name "LetAppsAccessVideos" -Value 2 -Type DWord
    
    # Clear force-allow/deny lists
    $nullLists = @("LetAppsAccessVideos_UserInControlOfTheseApps", "LetAppsAccessVideos_ForceAllowTheseApps", "LetAppsAccessVideos_ForceDenyTheseApps")
    foreach ($list in $nullLists) { Set-ItemProperty -Path $policyPath -Name $list -Value $null -Type MultiString -ErrorAction SilentlyContinue }

    # 2. Set Consent Store to Deny
    if (-not (Test-Path $consentPath)) { New-Item -Path $consentPath -Force | Out-Null }
    Set-ItemProperty -Path $consentPath -Name "Value" -Value "Deny"

    # 3. Hard-Lock Legacy GUID
    if (-not (Test-Path $guidPath)) { New-Item -Path $guidPath -Force | Out-Null }
    Set-ItemProperty -Path $guidPath -Name "Value" -Value "Deny"

    Write-Host "SUCCESS: Access to Videos is now LOCKED." -ForegroundColor Yellow
}
else {
    Write-Host "Aborted: Invalid Input." -ForegroundColor Red
}

Write-Host "`nDone." -ForegroundColor Cyan

# Top Header
Write-Host " ===================================================== " -ForegroundColor Cyan
Write-Host "    ⚡ CONGRATULATIONS DEAR: MISSION ACCOMPLISHED ⚡     " -ForegroundColor White -BackgroundColor DarkBlue
Write-Host " ===================================================== " -ForegroundColor Cyan

# My Personal Message
Write-Host ""
Write-Host " [>] " -NoNewline -ForegroundColor White; Write-Host "STATUS : " -NoNewline -ForegroundColor Cyan; Write-Host "SYSTEM DEVASTATED & REBORN" -ForegroundColor Green
Write-Host " [>] " -NoNewline -ForegroundColor White; Write-Host "MESSAGE: " -NoNewline -ForegroundColor Cyan; Write-Host "I hope your system is now free from lag and" -ForegroundColor White
Write-Host "            experiencing smooth, elite performance." -ForegroundColor White
Write-Host ""

# The Iconic WinRaze Gradient Logo (The "Wow" Factor)
Write-Host "  __      __.__          __________                     " -ForegroundColor Cyan
Write-Host " /  \    /  \__| ____   \______   \_____  ________ ____ " -ForegroundColor Cyan
Write-Host " \   \/\/   /  |/    \   |       _/\__  \ \___   // __ \" -ForegroundColor White
Write-Host "  \        /|  |   |  \  |    |   \ / __ \_/    /\  ___/" -ForegroundColor Blue
Write-Host "   \__/\  / |__|___|  /  |____|_  /(____  /_____ \\___  >" -ForegroundColor DarkBlue
Write-Host "        \/          \/          \/      \/      \/    \/ " -ForegroundColor DarkBlue

# Credits
Write-Host ""
Write-Host " [★] Created by: " -NoNewline -ForegroundColor White; Write-Host "Cyberkun (Rohit Kr. Mandal)" -ForegroundColor Green
Write-Host " ----------------------------------------------------- " -ForegroundColor Gray

# The Final Interactive Prompt
Write-Host ""
Write-Host " Press any key to continue our WinRaze terminal for SOFTWARE INSTALLATION PROCESS" -ForegroundColor Gray

# Secure Terminal Hold
$null = [Console]::ReadKey($true)

# Setup Security & Folders
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$desktop = [Environment]::GetFolderPath("Desktop")
$folder = "$desktop\WinRaze_Tools"
if (!(Test-Path $folder)) { New-Item -ItemType Directory -Path $folder | Out-Null }

# Update your Download function with this logic for better feedback
function Download-WinRazeTool {
    param($url, $fileName)
    $fullPath = Join-Path $folder $fileName
    
    Write-Host "`n [*] Establishing Secure Connection to Vault..." -ForegroundColor Yellow
    Write-Host " [!] Speed depends on your Connection. Please wait..." -ForegroundColor DarkGray
    
    try {
        # This command triggers the built-in progress bar
        Invoke-WebRequest -Uri $url -OutFile $fullPath -UserAgent "Mozilla/5.0" -MaximumRedirection 5 -ErrorAction Stop
        
        $sizeMB = [Math]::Round((Get-Item $fullPath).Length / 1MB, 2)
        Write-Host " [SUCCESS] Received $fileName" -ForegroundColor Green
        Write-Host " [INFO] Total Data: $sizeMB MB" -ForegroundColor Cyan
    } catch {
        Write-Host " [FAILED] Connection Timed Out or Interrupted." -ForegroundColor Red
        Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Gray
    }
}

# TOOL 1
$choice = Read-Host " [?] Download ToolWiz Time Freeze? (Y/N)"
if ($choice -eq "Y" -or $choice -eq "y") {
    Download-WinRazeTool -url "https://github.com/Rohit5984/Software/releases/download/v1.0.0/ToolWiz.Time.Freeze.exe" -fileName "ToolWiz_TimeFreeze.exe"
}

# TOOL 2
$choice = Read-Host " [?] Download Outbyte Camomile? (Y/N)"
if ($choice -eq "Y" -or $choice -eq "y") {
    Download-WinRazeTool -url "https://github.com/Rohit5984/Software/releases/download/v1.0.0/Outbyte.Camomile.CPU.cooler.long.battery.life.exe" -fileName "Camomile_Cooler.exe"
}

# TOOL 3
$choice = Read-Host " [?] Download Thorium Browser? (Y/N)"
if ($choice -eq "Y" -or $choice -eq "y") {
    Download-WinRazeTool -url "https://github.com/Rohit5984/Software/releases/download/v1.0.0/Thorium_AVX_mini_installer.exe" -fileName "Thorium_Installer.exe"
}

Write-Host "`n [>] Process finished. Opening folder..." -ForegroundColor Gray
Start-Process explorer.exe $folder
Write-Host " Press any key to exit..." -ForegroundColor Gray
$null = [Console]::ReadKey($true)
