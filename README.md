# Parental Shield — Native Windows Parental Controls

**Parental Shield** is a 100% native Windows desktop application built in C# (.NET 10 & WPF) designed to help parents safeguard children by blocking 18+ adult websites, mature apps, gambling, and custom digital distractions.

---

## Why a Native Windows App? (No Terminal Window)

Traditional scripts or development servers leave an open Command Prompt or Terminal window on the screen. **Children quickly learn that clicking the `X` on the terminal window immediately kills the controls and unlocks restricted sites.**

**Parental Shield eliminates this completely:**
- **Zero Console / Terminal Window**: Built as a pure Windows GUI application (`WinExe`). There is no terminal, console, or command prompt window running anywhere.
- **Single Executable (`ParentalShield.exe`)**: Launches directly like any standard Windows program.
- **Embedded Administrator Manifest**: Automatically prompts Windows UAC on launch so it has direct, machine-wide power to manage the Windows network `hosts` file and terminate blocked processes.
- **Tamper-Proof Close Behavior**: Clicking the top-right `X` (Close) does **not** close protection. It safely hides the application into the **Windows System Tray** (Taskbar notification area) and automatically locks the dashboard so the child cannot tamper with settings.
- **Passcode-Protected Exit**: Terminating or modifying the app requires the parent's PIN.

---

## Key Highlights

- **Parent Passcode Protection**:
  - Hashed and salted using PBKDF2 (SHA-512, 100,000 iterations).
  - Virtual numeric keypad + physical keyboard support (0-9, Backspace, Enter, Esc).
  - Auto-lock timeout after idle time (1, 3, 5, or 10 minutes) or immediately upon minimizing to the system tray.
  - Security Recovery Question flow in case you forget your PIN.

- **System-Wide Browser Blocking (Chrome, Edge, Firefox, Brave)**:
  - Writes directly to `C:\Windows\System32\drivers\etc\hosts` with loopback routing (`0.0.0.0` and `::1`).
  - Instantly flushes the Windows DNS resolver cache via native Win32 API (`DnsFlushResolverCache`).
  - **Anti-Bypass Protection**: Automatically disables DNS-over-HTTPS (DoH) policies in Chrome, Edge, and Brave so browsers cannot secretly query external encrypted DNS to bypass the blocklist.
  - Pre-loaded with 85+ major adult video networks, explicit chat hubs, and cam sites.
  - Pre-loaded with online gambling, betting, and casino domains.
  - Add any custom domain with 1-click preset chips (+TikTok, +Instagram, +Twitter, +Reddit, +Twitch, +Roblox).

- **Real-Time Application Watchdog**:
  - Background asynchronous monitor checking running processes every 1.2 seconds.
  - Immediately terminates prohibited executables via process tree kill.
  - Pre-configured to block unmoderated P2P torrent clients (`uTorrent`, `BitTorrent`, `qBittorrent`), unrated video chat (`Omegle`), and adult dating apps.
  - **Running Apps Scanner**: Click *"Pick from Running Apps"* to see active programs on the computer and block any game with a single click.
  - Browse `.exe` button to select any file on disk.
  - Quick distraction presets for Roblox, Steam, Epic Games Launcher, Discord, and Telegram.

- **Dark & Light Mode**:
  - Clean theme switcher with instant high-contrast Light and Dark mode options.

- **Real-Time Activity Audit Trail**:
  - Live log of blocked application launches and domain changes with timestamps.

---

## Installation & Download

### Download Executable
Download the latest installer or portable executable from the [GitHub Releases](https://github.com/amirthekingofficial/ParentalShield/releases):
- **`ParentalShield-win-Setup.exe`**: Automatic installer with desktop shortcut and background auto-update support.
- **`ParentalShield-win-Portable.zip`**: Zero-install standalone portable edition.

### Running the App
1. Launch **`ParentalShield.exe`** (or the Desktop shortcut created by Setup).
2. Click **"Yes"** on the Windows UAC elevation prompt (required to manage hosts blocking and system watchdog).
3. The app starts directly in the system tray and status window with zero console/terminal windows.

### Building from Source
Requirements: [.NET 10 SDK](https://dotnet.microsoft.com/) on Windows 10/11.
```bash
dotnet build -c Release
```

