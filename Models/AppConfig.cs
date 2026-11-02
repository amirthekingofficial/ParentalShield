using System;
using System.Collections.Generic;

namespace ParentalShield.Models;

public class BlockedWebsite
{
    public string Domain { get; set; } = string.Empty;
    public string Category { get; set; } = "Custom Block";
    public bool Enabled { get; set; } = true;
    public DateTime AddedAt { get; set; } = DateTime.Now;
}

public class BlockedApp
{
    public string Name { get; set; } = string.Empty;
    public string ProcessName { get; set; } = string.Empty;
    public string Category { get; set; } = "Custom Application";
    public bool Enabled { get; set; } = true;
    public DateTime AddedAt { get; set; } = DateTime.Now;
}

public class SecurityConfig
{
    public string? PasscodeHash { get; set; }
    public string? Salt { get; set; }
    public string? Question { get; set; }
    public string? AnswerHash { get; set; }
    public string? AnswerSalt { get; set; }
}

public class AppStats
{
    public int TotalBlocksIntercepted { get; set; }
    public int AppsBlockedCount { get; set; }
    public int WebsitesBlockedCount { get; set; }
}

public class ActivityLogEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public string Type { get; set; } = "app"; // "app", "website", "security"
    public string Target { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
}

/// <summary>
/// Bedtime window. When enabled and a protected account is active during the window,
/// browsers and blocked categories are enforced more strictly.
/// </summary>
public class BedtimeSchedule
{
    public bool Enabled { get; set; } = false;
    /// <summary>Local time of day when bedtime starts (e.g. 21:00).</summary>
    public string StartTime { get; set; } = "21:00";
    /// <summary>Local time of day when bedtime ends (e.g. 07:00).</summary>
    public string EndTime { get; set; } = "07:00";
    /// <summary>When true, closes common browsers for protected accounts during bedtime.</summary>
    public bool CloseBrowsersDuringBedtime { get; set; } = true;
}

public class AppConfig
{
    public string Theme { get; set; } = "Dark"; // "Dark" or "Light"
    public bool ProtectionActive { get; set; } = true;
    public bool BlockAdultContent { get; set; } = true;
    public bool BlockGambling { get; set; } = true;
    public bool BlockMatureApps { get; set; } = true;
    public bool MinimizeToTray { get; set; } = true;
    public bool StartWithWindows { get; set; } = true;
    public int AutoLockMinutes { get; set; } = 3;

    /// <summary>
    /// When true (default), hosts / DNS / DoH changes and process kills only apply
    /// while a selected protected Windows account has an active session.
    /// Parent and other accounts keep normal DNS.
    /// </summary>
    public bool ScopeToProtectedAccounts { get; set; } = true;

    /// <summary>
    /// Windows account usernames (SAM account names) that parental controls apply to.
    /// Empty + ScopeToProtectedAccounts = protection armed but idle until accounts are chosen.
    /// </summary>
    public List<string> ProtectedWindowsAccounts { get; set; } = new();

    public bool BlockSocialMedia { get; set; } = false;
    public bool BlockVpnAndProxies { get; set; } = true;
    public bool ForceSafeSearch { get; set; } = true;
    public bool BlockPrivateBrowsing { get; set; } = true;
    /// <summary>
    /// Disables DNS-over-HTTPS in protected child browser profiles via policy only.
    /// Must never redirect public DNS hostnames through the Windows hosts file.
    /// </summary>
    public bool BlockDnsTampering { get; set; } = true;

    public BedtimeSchedule Bedtime { get; set; } = new();

    /// <summary>Optional temporary pause end time (UTC ticks). Null when not paused.</summary>
    public long? TemporaryPauseUntilUtcTicks { get; set; }

    public SecurityConfig Security { get; set; } = new();
    public AppStats Stats { get; set; } = new();

    public List<BlockedWebsite> CustomWebsites { get; set; } = new()
    {
        new BlockedWebsite { Domain = "omegle.com", Category = "Unmoderated Chat" },
        new BlockedWebsite { Domain = "chatrandom.com", Category = "Unmoderated Chat" }
    };

    public List<BlockedApp> CustomApps { get; set; } = new()
    {
        new BlockedApp { Name = "Discord", ProcessName = "Discord.exe", Category = "Social / Chat", Enabled = false }
    };

    public bool IsTemporarilyPaused()
    {
        if (TemporaryPauseUntilUtcTicks == null) return false;
        if (DateTime.UtcNow.Ticks >= TemporaryPauseUntilUtcTicks.Value)
        {
            TemporaryPauseUntilUtcTicks = null;
            return false;
        }
        return true;
    }
}
