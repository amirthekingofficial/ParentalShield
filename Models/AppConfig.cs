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
}
