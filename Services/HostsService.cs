using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using ParentalShield.Models;

namespace ParentalShield.Services;

public class HostsService
{
    private const string BlockHeader = "# === PARENTAL SHIELD MANAGED BLOCKS (DO NOT MODIFY) ===";
    private const string BlockFooter = "# === END PARENTAL SHIELD MANAGED BLOCKS ===";
    private readonly string _hostsPath;
    private readonly string _backupPath;
    private readonly ConfigService _configService;
    private readonly AccountScopeService _accountScope;
    private bool? _lastAppliedState;

    // Win32 API for instantaneous DNS resolver cache flush
    [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache", SetLastError = true)]
    private static extern int DnsFlushResolverCache();

    public HostsService(ConfigService configService, AccountScopeService accountScope)
    {
        _configService = configService;
        _accountScope = accountScope;
        string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        _hostsPath = Path.Combine(sysRoot, "System32", "drivers", "etc", "hosts");
        _backupPath = Path.Combine(configService.ConfigDir, "hosts.original.bak");
        EnsureBackup();
    }

    private void EnsureBackup()
    {
        try
        {
            if (!File.Exists(_backupPath) && File.Exists(_hostsPath))
            {
                File.Copy(_hostsPath, _backupPath, true);
            }
        }
        catch (Exception ex)
        {
            App.LogDebug($"Backup error: {ex.Message}");
        }
    }

    public List<string> GetActiveDomains()
    {
        var config = _configService.Config;
        if (!config.ProtectionActive || config.IsTemporarilyPaused()) return [];

        // When scoped to protected accounts and none are online, report 0 active domains
        // (machine hosts file should also be clean — see SyncEnforcement).
        if (config.ScopeToProtectedAccounts && !_accountScope.ShouldEnforceNetworkBlocks())
            return [];

        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (config.BlockAdultContent)
        {
            foreach (var d in DefaultBlocklists.AdultDomains)
                set.Add(d.Trim());
        }

        if (config.BlockGambling)
        {
            foreach (var d in DefaultBlocklists.GamblingDomains)
                set.Add(d.Trim());
        }

        if (config.BlockSocialMedia)
        {
            foreach (var d in DefaultBlocklists.SocialMediaDomains)
                set.Add(d.Trim());
        }

        if (config.BlockVpnAndProxies)
        {
            foreach (var d in DefaultBlocklists.VpnProxyDomains)
                set.Add(d.Trim());
        }

        // DoH provider hosts blocks are a last-resort anti-bypass for child sessions only.
        // They are never left in place when parent accounts are the only ones logged on.
        if (_accountScope.ShouldEnforceNetworkBlocks() && config.BlockDnsTampering)
        {
            foreach (var doh in DefaultBlocklists.DoHProviders)
                set.Add(doh.Trim());
        }

        foreach (var custom in config.CustomWebsites)
        {
            if (custom.Enabled && !string.IsNullOrWhiteSpace(custom.Domain))
            {
                set.Add(custom.Domain.Trim());
            }
        }

        return [.. set];
    }

    public void FlushDns()
    {
        try
        {
            DnsFlushResolverCache();
        }
        catch
        {
        }

        try
        {
            var psi = new ProcessStartInfo("ipconfig", "/flushdns")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using var p = Process.Start(psi);
            p?.WaitForExit(1500);
        }
        catch
        {
        }
    }

    public string CleanHostsText(string content)
    {
        int startIndex = content.IndexOf(BlockHeader, StringComparison.Ordinal);
        int endIndex = content.IndexOf(BlockFooter, StringComparison.Ordinal);

        if (startIndex != -1 && endIndex != -1)
        {
            string before = content[..startIndex].TrimEnd();
            string after = content[(endIndex + BlockFooter.Length)..].TrimStart();
            return (before + (string.IsNullOrEmpty(after) ? "" : "\r\n" + after)).TrimEnd() + "\r\n";
        }
        return content.TrimEnd() + "\r\n";
    }

    /// <summary>
    /// Applies or clears hosts rules based on whether a protected child session is active.
    /// Parent-only sessions get a clean hosts file so their DNS is not ruined.
    /// </summary>
    public bool SyncEnforcement(bool force = false)
    {
        bool shouldApply = _accountScope.ShouldEnforceNetworkBlocks();
        if (!force && _lastAppliedState == shouldApply)
            return true;

        bool ok = shouldApply ? ApplyBlockRulesInternal() : RestoreOriginalInternal();
        if (ok) _lastAppliedState = shouldApply;
        return ok;
    }

    public bool ApplyBlockRules()
    {
        // Public entry used by UI — always re-evaluate account scope
        _lastAppliedState = null;
        return SyncEnforcement(force: true);
    }

    public bool RestoreOriginal()
    {
        _lastAppliedState = null;
        bool ok = RestoreOriginalInternal();
        if (ok) _lastAppliedState = false;
        return ok;
    }

    private bool ApplyBlockRulesInternal()
    {
        try
        {
            string currentContent = File.Exists(_hostsPath) ? File.ReadAllText(_hostsPath) : "";
            string cleanContent = CleanHostsText(currentContent);
            var domains = BuildDomainListForHosts();

            var sb = new StringBuilder();
            if (domains.Count > 0)
            {
                sb.AppendLine(BlockHeader);
                sb.AppendLine($"# Total active blocked domains: {domains.Count}");
                sb.AppendLine($"# Last updated: {DateTime.Now}");
                sb.AppendLine("# Scoped: only while a protected child Windows account is signed in.");

                foreach (var raw in domains)
                {
                    string d = raw.Replace("http://", "").Replace("https://", "").Split('/')[0].Trim().ToLowerInvariant();
                    if (string.IsNullOrWhiteSpace(d)) continue;

                    sb.AppendLine($"0.0.0.0 {d}");
                    sb.AppendLine($"::1 {d}");

                    if (!d.StartsWith("www."))
                    {
                        sb.AppendLine($"0.0.0.0 www.{d}");
                        sb.AppendLine($"::1 www.{d}");
                    }
                }

                sb.AppendLine(BlockFooter);
            }

            string finalContent = cleanContent + (sb.Length > 0 ? "\r\n" + sb.ToString() : "");
            File.WriteAllText(_hostsPath, finalContent, Encoding.UTF8);

            FlushDns();
            App.LogDebug($"Hosts block rules applied ({domains.Count} domains) for protected sessions");
            return true;
        }
        catch (Exception ex)
        {
            App.LogDebug($"Error applying block rules to hosts: {ex.Message}");
            return false;
        }
    }

    private List<string> BuildDomainListForHosts()
    {
        var config = _configService.Config;
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (config.BlockAdultContent)
        {
            foreach (var d in DefaultBlocklists.AdultDomains)
                set.Add(d.Trim());
        }

        if (config.BlockGambling)
        {
            foreach (var d in DefaultBlocklists.GamblingDomains)
                set.Add(d.Trim());
        }

        if (config.BlockSocialMedia)
        {
            foreach (var d in DefaultBlocklists.SocialMediaDomains)
                set.Add(d.Trim());
        }

        if (config.BlockVpnAndProxies)
        {
            foreach (var d in DefaultBlocklists.VpnProxyDomains)
                set.Add(d.Trim());
        }

        if (config.BlockDnsTampering)
        {
            foreach (var doh in DefaultBlocklists.DoHProviders)
                set.Add(doh.Trim());
        }

        foreach (var custom in config.CustomWebsites)
        {
            if (custom.Enabled && !string.IsNullOrWhiteSpace(custom.Domain))
                set.Add(custom.Domain.Trim());
        }

        return [.. set];
    }

    private bool RestoreOriginalInternal()
    {
        try
        {
            if (File.Exists(_hostsPath))
            {
                string currentContent = File.ReadAllText(_hostsPath);
                string cleanContent = CleanHostsText(currentContent);
                File.WriteAllText(_hostsPath, cleanContent, Encoding.UTF8);
                FlushDns();
                App.LogDebug("Hosts Parental Shield block section removed — DNS restored for other accounts");
            }
            return true;
        }
        catch (Exception ex)
        {
            App.LogDebug("RestoreOriginal hosts error: " + ex.Message);
            return false;
        }
    }
}
