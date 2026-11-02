using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;
using ParentalShield.Models;

namespace ParentalShield.Services;

/// <summary>
/// Applies browser / DoH / SafeSearch policies to protected users' HKCU hives only,
/// and removes leftover machine-wide (HKLM) DoH policies that broke other accounts.
/// </summary>
public class BrowserPolicyService
{
    private readonly ConfigService _configService;
    private readonly AccountScopeService _accountScope;

    private static readonly string[] ChromePolicyPaths =
    [
        @"Software\Policies\Google\Chrome",
        @"Software\Policies\Microsoft\Edge",
        @"Software\Policies\BraveSoftware\Brave"
    ];

    public BrowserPolicyService(ConfigService configService, AccountScopeService accountScope)
    {
        _configService = configService;
        _accountScope = accountScope;
    }

    /// <summary>Removes machine-wide DoH kills that affected every Windows account.</summary>
    public void ClearMachineWideDoHPolicies()
    {
        try
        {
            DeleteHkLmValue(@"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode");
            DeleteHkLmValue(@"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode");
            DeleteHkLmValue(@"SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode");
            App.LogDebug("Cleared machine-wide (HKLM) DoH policies");
        }
        catch (Exception ex)
        {
            App.LogDebug("ClearMachineWideDoHPolicies: " + ex.Message);
        }
    }

    private static void DeleteHkLmValue(string subKey, string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKey, writable: true);
            key?.DeleteValue(valueName, throwOnMissingValue: false);
        }
        catch
        {
        }
    }

    /// <summary>
    /// Sync per-user browser policies for protected accounts.
    /// When not enforcing, clears policies from protected hives so Fast User Switching
    /// back to a parent does not leave child-only prefs on the wrong profile.
    /// Policies are written into each protected user's hive via LoadUserProfile path / Registry.
    /// </summary>
    public void SyncProtectedUserPolicies(bool enforce)
    {
        var config = _configService.Config;
        var accounts = _accountScope.GetLocalUserAccounts();
        var protectedNames = new HashSet<string>(
            config.ProtectedWindowsAccounts ?? new List<string>(),
            StringComparer.OrdinalIgnoreCase);

        bool active = enforce && config.ProtectionActive && !config.IsTemporarilyPaused();

        foreach (var account in accounts)
        {
            bool isProtected = protectedNames.Contains(account.UserName);

            // In scoped mode, never write into parent/other hives during the periodic loop.
            // (Removing a child from the list clears that hive once via ClearUserPolicies.)
            if (config.ScopeToProtectedAccounts && !isProtected)
                continue;

            bool shouldApply = active && (!config.ScopeToProtectedAccounts || isProtected);

            try
            {
                ApplyToUserHive(account, shouldApply);
            }
            catch (Exception ex)
            {
                App.LogDebug($"Policy sync for {account.UserName}: {ex.Message}");
            }
        }

        // Live HKCU for the account running Parental Shield
        string current = AccountScopeService.GetCurrentUserName();
        bool currentApply = active && (!config.ScopeToProtectedAccounts || protectedNames.Contains(current));
        ApplyToCurrentUser(currentApply);
    }

    /// <summary>Clears browser policies for one Windows account (e.g. after un-marking as protected).</summary>
    public void ClearUserPolicies(string userName)
    {
        var account = _accountScope.GetLocalUserAccounts()
            .Find(a => a.UserName.Equals(userName, StringComparison.OrdinalIgnoreCase));
        if (account == null) return;

        try
        {
            ApplyToUserHive(account, enforce: false);
            if (userName.Equals(AccountScopeService.GetCurrentUserName(), StringComparison.OrdinalIgnoreCase))
                ApplyToCurrentUser(enforce: false);
        }
        catch (Exception ex)
        {
            App.LogDebug($"ClearUserPolicies({userName}): {ex.Message}");
        }
    }

    private void ApplyToCurrentUser(bool enforce)
    {
        foreach (var path in ChromePolicyPaths)
        {
            WriteBrowserPolicies(Registry.CurrentUser, path, enforce);
        }
    }

    private void ApplyToUserHive(WindowsAccountInfo account, bool enforce)
    {
        if (string.IsNullOrWhiteSpace(account.Sid)) return;

        // Logged-on users expose HKU\{SID}
        using var hku = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        using var userKey = hku.OpenSubKey(account.Sid, writable: true);
        if (userKey != null)
        {
            foreach (var path in ChromePolicyPaths)
            {
                WriteBrowserPolicies(userKey, path, enforce);
            }
            return;
        }

        // Offline user: load NTUSER.DAT temporarily
        string? profilePath = GetProfilePath(account.Sid);
        if (string.IsNullOrWhiteSpace(profilePath)) return;
        string ntuser = Path.Combine(profilePath, "NTUSER.DAT");
        if (!File.Exists(ntuser)) return;

        string tempName = "PS_" + account.Sid.Replace('-', '_');
        try
        {
            int rc = NativeMethods.RegLoadKey(NativeMethods.HKEY_USERS, tempName, ntuser);
            if (rc != 0)
            {
                App.LogDebug($"RegLoadKey {account.UserName} rc={rc}");
                return;
            }

            using var loaded = hku.OpenSubKey(tempName, writable: true);
            if (loaded == null) return;

            foreach (var path in ChromePolicyPaths)
            {
                WriteBrowserPolicies(loaded, path, enforce);
            }
        }
        finally
        {
            NativeMethods.RegUnLoadKey(NativeMethods.HKEY_USERS, tempName);
        }
    }

    private void WriteBrowserPolicies(RegistryKey root, string relativePath, bool enforce)
    {
        var config = _configService.Config;

        if (!enforce)
        {
            try
            {
                using var key = OpenOrCreate(root, relativePath);
                if (key == null) return;
                key.DeleteValue("DnsOverHttpsMode", false);
                key.DeleteValue("DnsOverHttpsTemplates", false);
                key.DeleteValue("IncognitoModeAvailability", false);
                key.DeleteValue("ForceGoogleSafeSearch", false);
                key.DeleteValue("ForceYouTubeRestrict", false);
                key.DeleteValue("SafeSearchEnabled", false); // Edge
            }
            catch
            {
            }
            return;
        }

        using var policyKey = OpenOrCreate(root, relativePath);
        if (policyKey == null) return;

        // Per-user DoH off only — NEVER via hosts file (that broke system DNS for everyone)
        if (config.BlockDnsTampering)
        {
            policyKey.SetValue("DnsOverHttpsMode", "off", RegistryValueKind.String);
        }
        else
        {
            policyKey.DeleteValue("DnsOverHttpsMode", false);
            policyKey.DeleteValue("DnsOverHttpsTemplates", false);
        }

        if (config.BlockPrivateBrowsing)
        {
            // 1 = disabled
            policyKey.SetValue("IncognitoModeAvailability", 1, RegistryValueKind.DWord);
        }
        else
        {
            policyKey.DeleteValue("IncognitoModeAvailability", false);
        }

        if (config.ForceSafeSearch)
        {
            policyKey.SetValue("ForceGoogleSafeSearch", 1, RegistryValueKind.DWord);
            policyKey.SetValue("ForceYouTubeRestrict", 1, RegistryValueKind.DWord);
        }
        else
        {
            policyKey.DeleteValue("ForceGoogleSafeSearch", false);
            policyKey.DeleteValue("ForceYouTubeRestrict", false);
        }
    }

    private static RegistryKey? OpenOrCreate(RegistryKey root, string path)
    {
        try
        {
            return root.CreateSubKey(path, true);
        }
        catch
        {
            return null;
        }
    }

    private static string? GetProfilePath(string sid)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid);
            return key?.GetValue("ProfileImagePath") as string;
        }
        catch
        {
            return null;
        }
    }

    private static class NativeMethods
    {
        public static readonly IntPtr HKEY_USERS = new IntPtr(unchecked((int)0x80000003));

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        public static extern int RegLoadKey(IntPtr hKey, string lpSubKey, string lpFile);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        public static extern int RegUnLoadKey(IntPtr hKey, string lpSubKey);
    }
}
