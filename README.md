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

- **Account-Scoped Browser Blocking (Chrome, Edge, Firefox, Brave)**:
  - Select which Windows accounts are protected children. Parent and other desktop accounts keep normal DNS.
  - Hosts rules are applied only while a protected child session is signed in, then cleared automatically when those accounts log off.
  - **DNS-safe by design**: public DNS/DoH hostnames (`dns.google`, `one.one.one.one`, etc.) are never redirected in the hosts file. Flushes happen only when hosts content actually changes. Startup always repairs leftover redirects.
  - **Anti-Bypass Protection**: Disables DNS-over-HTTPS (DoH), Incognito/InPrivate, and forces SafeSearch in the *child account's* browser profiles only — not via machine-wide policies or hosts redirects that break other users.
  - Built-in **Repair DNS now** button for one-click cleanup if browsing ever acts up.
  - Pre-loaded with 85+ major adult video networks, explicit chat hubs, and cam sites.
  - Pre-loaded with online gambling, betting, casino, social media, and VPN/proxy domains.
  - Add any custom domain with 1-click preset chips (+TikTok, +Instagram, +Twitter, +Reddit, +Twitch, +Roblox).

- **Parent Control Center**:
  - Protected Windows account picker with live scope status.
  - Bedtime schedule that can close browsers for child accounts overnight.
  - Temporary pause (15 min / 1 hour) that restores DNS for everyone until it expires.
  - Toggles for SafeSearch, private browsing, DNS bypass blocking, social media, and VPNs.

- **Real-Time Application Watchdog**:
  - Background asynchronous monitor checking running processes every 1.2 seconds.
  - Terminates prohibited executables only when they belong to a protected child account.
  - Pre-configured to block unmoderated P2P torrent clients (`uTorrent`, `BitTorrent`, `qBittorrent`), unrated video chat (`Omegle`), adult dating apps, and common VPN clients.
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

### Getting updates (installed app)
**Check for updates only finds versions that are published on GitHub Releases.** Merging code to `main` is not enough by itself.

1. Publish a new release (see below) — e.g. `v1.1.1`
2. In the app: **Settings → Check for updates** → download & restart  
   Or reinstall with the new `ParentalShield-win-Setup.exe` from Releases

If Check for updates says you’re current, there is no newer Velopack release uploaded yet (right now the store still only has `v1.0.1` until you publish `1.1.1`).

### Publishing a release (easy)
Use the **Release** GitHub Action — it builds Windows packages with Velopack and uploads them so installed apps can update:

1. Open [Actions → Release](https://github.com/amirthekingofficial/ParentalShield/actions/workflows/release.yml)
2. Click **Run workflow**
3. Version: `1.1.1` (or leave blank to use the `<Version>` in `ParentalShield.csproj`)
4. Wait for the job to finish, then confirm the new release appears under [Releases](https://github.com/amirthekingofficial/ParentalShield/releases)

Or from git:
```bash
git tag v1.1.1
git push origin v1.1.1
```

### Running the App
1. Launch **`ParentalShield.exe`** (or the Desktop shortcut created by Setup).
2. Click **"Yes"** on the Windows UAC elevation prompt (required to manage hosts blocking and system watchdog).
3. The app starts directly in the system tray and status window with zero console/terminal windows.

### Building from Source
Requirements: [.NET 10 SDK](https://dotnet.microsoft.com/) on Windows 10/11.
```bash
dotnet build -c Release
```

