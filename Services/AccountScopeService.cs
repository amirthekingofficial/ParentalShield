using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace ParentalShield.Services;

public class WindowsAccountInfo
{
    public string UserName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Sid { get; set; } = string.Empty;
    public bool IsCurrentUser { get; set; }
}

/// <summary>
/// Resolves which Windows accounts are under parental control and which sessions
/// are currently active, so DNS / hosts / process kills stay off parent accounts.
/// </summary>
public class AccountScopeService
{
    private readonly ConfigService _configService;

    private const int WTS_CURRENT_SERVER_HANDLE = 0;
    private const int WTSUserName = 5;

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(
        IntPtr hServer,
        int Reserved,
        int Version,
        out IntPtr ppSessionInfo,
        out int pCount);

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr hServer,
        int sessionId,
        int wtsInfoClass,
        out IntPtr ppBuffer,
        out int pBytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public int State;
    }

    public AccountScopeService(ConfigService configService)
    {
        _configService = configService;
    }

    public static string GetCurrentUserName()
    {
        try
        {
            string name = Environment.UserName;
            return name ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// Local interactive user profiles from the ProfileList registry (excludes system accounts).
    /// </summary>
    public List<WindowsAccountInfo> GetLocalUserAccounts()
    {
        var results = new List<WindowsAccountInfo>();
        string current = GetCurrentUserName();

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
            if (key == null) return FallbackCurrentOnly(current);

            foreach (string sid in key.GetSubKeyNames())
            {
                // Skip built-in / service SIDs (S-1-5-18 LocalSystem, 19 LocalService, 20 NetworkService)
                if (sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20") continue;
                if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)) continue;

                try
                {
                    using var sub = key.OpenSubKey(sid);
                    string? profilePath = sub?.GetValue("ProfileImagePath") as string;
                    if (string.IsNullOrWhiteSpace(profilePath)) continue;

                    string userName = Path.GetFileName(profilePath.TrimEnd('\\'));
                    if (string.IsNullOrWhiteSpace(userName)) continue;
                    if (userName.Equals("systemprofile", StringComparison.OrdinalIgnoreCase)) continue;
                    if (userName.Equals("LocalService", StringComparison.OrdinalIgnoreCase)) continue;
                    if (userName.Equals("NetworkService", StringComparison.OrdinalIgnoreCase)) continue;

                    string display = userName;
                    try
                    {
                        var account = new SecurityIdentifier(sid).Translate(typeof(NTAccount));
                        string full = account.Value;
                        int slash = full.LastIndexOf('\\');
                        if (slash >= 0 && slash < full.Length - 1)
                            userName = full[(slash + 1)..];
                        display = full;
                    }
                    catch
                    {
                        // Profile folder name is fine as fallback
                    }

                    if (results.Any(r => r.UserName.Equals(userName, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    results.Add(new WindowsAccountInfo
                    {
                        UserName = userName,
                        DisplayName = display,
                        Sid = sid,
                        IsCurrentUser = userName.Equals(current, StringComparison.OrdinalIgnoreCase)
                    });
                }
                catch
                {
                }
            }
        }
        catch (Exception ex)
        {
            App.LogDebug("GetLocalUserAccounts error: " + ex.Message);
            return FallbackCurrentOnly(current);
        }

        if (results.Count == 0)
            return FallbackCurrentOnly(current);

        return results.OrderBy(a => a.UserName, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static List<WindowsAccountInfo> FallbackCurrentOnly(string current)
    {
        if (string.IsNullOrWhiteSpace(current)) return new List<WindowsAccountInfo>();
        return
        [
            new WindowsAccountInfo
            {
                UserName = current,
                DisplayName = current,
                IsCurrentUser = true
            }
        ];
    }

    /// <summary>Usernames with an active (or disconnected) Windows session.</summary>
    public HashSet<string> GetLoggedOnUserNames()
    {
        var users = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            if (WTSEnumerateSessions(IntPtr.Zero, 0, 1, out IntPtr pSessionInfo, out int count))
            {
                int size = Marshal.SizeOf<WTS_SESSION_INFO>();
                for (int i = 0; i < count; i++)
                {
                    var info = Marshal.PtrToStructure<WTS_SESSION_INFO>(pSessionInfo + (i * size));
                    // 0 = Active, 4 = Disconnected (Fast User Switching) — both keep a session
                    if (info.State is not (0 or 4)) continue;
                    if (info.SessionId == 0) continue; // Services session

                    if (WTSQuerySessionInformation(IntPtr.Zero, info.SessionId, WTSUserName, out IntPtr buffer, out int bytes) && buffer != IntPtr.Zero)
                    {
                        try
                        {
                            string? name = Marshal.PtrToStringUni(buffer);
                            if (!string.IsNullOrWhiteSpace(name))
                                users.Add(name.Trim());
                        }
                        finally
                        {
                            WTSFreeMemory(buffer);
                        }
                    }
                }
                WTSFreeMemory(pSessionInfo);
            }
        }
        catch (Exception ex)
        {
            App.LogDebug("WTSEnumerateSessions failed: " + ex.Message);
        }

        // Always include the process owner as a session (WTS can miss elevated edge cases)
        string current = GetCurrentUserName();
        if (!string.IsNullOrWhiteSpace(current))
            users.Add(current);

        return users;
    }

    public bool IsProtectedAccount(string userName)
    {
        if (string.IsNullOrWhiteSpace(userName)) return false;
        var list = _configService.Config.ProtectedWindowsAccounts;
        return list.Any(a => a.Equals(userName.Trim(), StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// True when hosts / DoH / network blocks should be written right now.
    /// Respects master switch, temporary pause, account scope, and whether a child is logged on.
    /// </summary>
    public bool ShouldEnforceNetworkBlocks()
    {
        var config = _configService.Config;
        if (!config.ProtectionActive) return false;
        if (config.IsTemporarilyPaused()) return false;

        if (!config.ScopeToProtectedAccounts)
            return true;

        if (config.ProtectedWindowsAccounts.Count == 0)
            return false; // Armed but idle — do not touch machine DNS until a child account is selected

        var loggedOn = GetLoggedOnUserNames();
        return config.ProtectedWindowsAccounts.Any(a => loggedOn.Contains(a));
    }

    /// <summary>True when process watchdog should terminate blocked apps for a given owner.</summary>
    public bool ShouldEnforceAgainstUser(string? processOwnerUserName)
    {
        var config = _configService.Config;
        if (!config.ProtectionActive) return false;
        if (config.IsTemporarilyPaused()) return false;

        if (!config.ScopeToProtectedAccounts)
            return true;

        if (config.ProtectedWindowsAccounts.Count == 0)
            return false;

        if (string.IsNullOrWhiteSpace(processOwnerUserName))
            return false;

        return IsProtectedAccount(processOwnerUserName);
    }

    public bool IsBedtimeNow()
    {
        var bed = _configService.Config.Bedtime;
        if (!bed.Enabled) return false;

        if (!TimeSpan.TryParse(bed.StartTime, out var start)) start = new TimeSpan(21, 0, 0);
        if (!TimeSpan.TryParse(bed.EndTime, out var end)) end = new TimeSpan(7, 0, 0);

        var now = DateTime.Now.TimeOfDay;
        if (start == end) return true;

        // Window may wrap midnight (21:00 → 07:00)
        if (start < end)
            return now >= start && now < end;
        return now >= start || now < end;
    }

    public static string? TryGetProcessOwner(Process process)
    {
        try
        {
            // Prefer WMI when available (reliable across sessions when running elevated)
            string query = $"SELECT * FROM Win32_Process WHERE ProcessId = {process.Id}";
            using var searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject obj in searcher.Get())
            {
                var args = new object?[] { string.Empty, string.Empty };
                var returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", args));
                if (returnVal == 0 && args[0] is string user && !string.IsNullOrWhiteSpace(user))
                    return user;
            }
        }
        catch
        {
        }

        try
        {
            const uint TOKEN_QUERY = 0x0008;
            if (!OpenProcessToken(process.Handle, TOKEN_QUERY, out IntPtr tokenHandle))
                return null;

            try
            {
                using var wi = new WindowsIdentity(tokenHandle);
                string? name = wi.Name;
                if (string.IsNullOrWhiteSpace(name)) return null;
                int slash = name.LastIndexOf('\\');
                return slash >= 0 ? name[(slash + 1)..] : name;
            }
            finally
            {
                CloseHandle(tokenHandle);
            }
        }
        catch
        {
            return null;
        }
    }

    public string DescribeScopeStatus()
    {
        var config = _configService.Config;
        if (!config.ProtectionActive)
            return "Protection paused — DNS unchanged for all accounts";

        if (config.IsTemporarilyPaused())
            return "Temporarily paused — DNS restored for all accounts";

        if (!config.ScopeToProtectedAccounts)
            return "Machine-wide mode — blocks apply to every Windows account";

        if (config.ProtectedWindowsAccounts.Count == 0)
            return "Select protected child accounts — DNS left alone until then";

        if (ShouldEnforceNetworkBlocks())
        {
            var active = config.ProtectedWindowsAccounts
                .Where(a => GetLoggedOnUserNames().Contains(a))
                .ToList();
            return $"Enforcing for: {string.Join(", ", active)} — other accounts keep normal DNS";
        }

        return "Protected accounts offline — parent DNS left alone";
    }
}
