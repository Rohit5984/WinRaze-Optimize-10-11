<p align="center">
  <img src="assets/Rohit.png" width="400" alt="WinRaze">
</p>
<p align="center">
  <strong>WinRaze – Nexus Edition</strong>
</p>

<!-- Step 1: WinUtil images -->
<p align="center">
  <img src="assets/Essential.png" width="300" alt="Essential">
  <img src="assets/Advanced.png" width="300" alt="Advanced">
  <img src="assets/Mine.png" width="300" alt="Mine">
</p>
<p align="center">
  <strong>Step 1: These three images are from WinUtil.ps1</strong>
</p>

<!-- Step 2: Performance tweaks -->
<p align="center">
  <img src="assets/Performance.png" width="400" alt="Performance">
</p>
<p align="center">
  <strong>Step 2: System Performance Tweaks – Virtual Memory</strong><br>
  Press <kbd>Windows + R</kbd>, type <code>SystemPropertiesPerformance</code>, and press <kbd>Enter</kbd>.<br>
  Follow the steps shown in the image, then open <strong>Advanced → Virtual Memory → Change…</strong> and:
</p>

<p align="center">
  - Uncheck <strong>Automatically manage paging file size for all drives</strong>.<br>
  - Select your system drive (usually C:) and choose <strong>Custom size</strong>.<br>
  - Set the initial and maximum sizes based on your installed RAM:
</p>

<p align="center">
  <strong>Examples</strong><br>
  - <strong>8 GB RAM</strong> → Initial = 12 GB (12 × 1024 = 12288 MB); Maximum = 24 GB (24 × 1024 = 24576 MB).<br>
  - <strong>16 GB RAM</strong> → Initial = 24 GB (24 × 1024 = 24576 MB); Maximum = 48 GB (48 × 1024 = 49152 MB).<br>
  - <strong>32 GB RAM</strong> → Initial = 48 GB (48 × 1024 = 49152 MB); Maximum = 96 GB (96 × 1024 = 98304 MB).
</p>

<p align="center">
  Click <strong>Set → OK</strong> to apply the changes.<br>
  Follow the steps shown in <strong>Performance.png</strong>.
</p>

<!-- Step 3: Registry Tweaks -->
<p align="center">
  <strong>Step 3: Registry Performance Tweaks</strong><br>
  Press <kbd>Windows + R</kbd>, type <code>regedit</code>, and press <kbd>Enter</kbd>.<br>
</p>

| Registry Path | Value | Change |
| :------------ | :---- | :----- |
| `HKCU\Control Panel\Mouse` | `MouseHoverTime` | `400 → 10` |
| `HKCU\Control Panel\Desktop` | `MenuShowDelay` | `400 → 10` |
| `HKLM\...\SystemProfile` | `SystemResponsiveness` | `14 → 0` |
| `HKLM\...\Tasks\Games` | `GPU Priority` | `8` |
| `HKLM\...\Tasks\Games` | `Priority` | `2 → 6` |

<p align="center">
  <strong>Final Step: Disable Unnecessary Startup Services</strong><br>
  <p align="center">
  <img src="assets/msconfig.png" width="400" alt="MSConfig">
</p>

  Press <kbd>Windows + R</kbd>, type <code>msconfig</code>, and press <kbd>Enter</kbd>.<br>
  Go to the <strong>Services</strong> tab.<br>
  ✔ Check <strong>Hide all Microsoft services</strong>.<br>
  ✔ Disable unnecessary third-party services only.<br>
  Click <strong>Apply → OK</strong>.
</p>

<p align="center">
  <strong>Restart your computer to apply all changes.</strong>
</p>

# 🌌 WinRaze Nexus Edition
### Universal Optimization Suite for Windows 10 and 11

**WinRaze** is a high-performance PowerShell utility developed by **Rohit Kr. Mandal** (alias: `CyberKun`). It is designed to remove unnecessary background processes and optimize Windows for gamers, developers, and power users.

[![GitHub stars](https://img.shields.io/github/stars/Rohit5984/WinRaze-Optimize-10-11?style=social)](https://github.com/Rohit5984/WinRaze-Optimize-10-11)
![Version](https://img.shields.io/badge/Version-1.0_BETA-magenta)
![License: MIT](https://img.shields.io/badge/License-MIT-cyan)
![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11-blue)

---

## 🛠 S-Rank Features
* **Neural-Raze**: Stops unnecessary background services and applies kernel-level tweaks for lower latency.
* **Ghost Protocol Privacy Hardening**: Locks selected registry keys to reduce background telemetry and limit intrusive permissions.
* **Nexus Interface**: A high-contrast, stylized terminal interface for a modern operator experience.

---

## Safety and Disclaimer
- These tweaks modify system settings and the registry. They can improve performance but may also cause instability if applied incorrectly.
- Always back up your data and create a system restore point before applying changes.
- Use the utility and manual tweaks at your own risk.

