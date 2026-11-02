using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace ParentalShield.Services;

public class HostsService
{
    private const string BlockHeader = "# === PARENTAL SHIELD MANAGED BLOCKS (DO NOT MODIFY) ===";
    private const string BlockFooter = "# === END PARENTAL SHIELD MANAGED BLOCKS ===";

    /// <summary>UTF-8 without BOM — a UTF-8 BOM in the Windows hosts file can break name resolution.</summary>
    private static readonly Encoding HostsEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    private readonly string _hostsPath;
    private readonly string _backupPath;
    private readonly ConfigService _configService;
    private readonly AccountScopeService _accountScope;
    private bool? _lastAppliedState;

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
                // Only backup a clean hosts file (never snapshot our own block section)
                string content = File.ReadAllText(_hostsPath);
                string clean = SanitizeHostsContent(content);
                File.WriteAllText(_backupPath, clean, HostsEncoding);
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

        if (config.ScopeToProtectedAccounts && !_accountScope.ShouldEnforceNetworkBlocks())
            return [];

        return BuildDomainListForHosts();
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

    /// <summary>
    /// Removes Parental Shield markers, orphaned block lines, and any leftover DoH hostname
    /// redirects that older builds left behind (those break internet for everyone).
    /// </summary>
    public string SanitizeHostsContent(string content)
    {
        if (string.IsNullOrEmpty(content))
            return "";

        // Strip UTF-8 BOM if present
        if (content.Length > 0 && content[0] == '\uFEFF')
            content = content[1..];

        content = CleanManagedBlockSection(content);
        content = StripDangerousDnsRedirects(content);
        return content.TrimEnd() + "\r\n";
    }

    private static string CleanManagedBlockSection(string content)
    {
        int startIndex = content.IndexOf(BlockHeader, StringComparison.Ordinal);
        if (startIndex == -1)
            return content;

        int endIndex = content.IndexOf(BlockFooter, StringComparison.Ordinal);
        if (endIndex != -1 && endIndex >= startIndex)
        {
            string before = content[..startIndex].TrimEnd();
            string after = content[(endIndex + BlockFooter.Length)..].TrimStart();
            return (before + (string.IsNullOrEmpty(after) ? "" : "\r\n" + after)).TrimEnd() + "\r\n";
        }

        // Footer missing (crash mid-write) — drop everything from the header onward
        return content[..startIndex].TrimEnd() + "\r\n";
    }

    /// <summary>
    /// Older builds mapped public DNS/DoH hostnames to 0.0.0.0 / ::1 in the hosts file.
    /// That randomly nukes browsing whenever Windows or a browser tries to use those names.
    /// Strip them even if they sit outside our managed markers.
    /// </summary>
    private static string StripDangerousDnsRedirects(string content)
    {
        var dangerous = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in DefaultBlocklists.DoHProviders)
            dangerous.Add(d.Trim().ToLowerInvariant());

        // Extra aliases that break system DNS when redirected to localhost
        dangerous.Add("one.one.one.one");
        dangerous.Add("1dot1dot1dot1.cloudflare-dns.com");
        dangerous.Add("dns.cloudflare.com");
        dangerous.Add("resolver1.opendns.com");
        dangerous.Add("resolver2.opendns.com");

        var lines = content.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        var kept = new List<string>(lines.Length);
        var hostLine = new Regex(
            @"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+(\S+)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        foreach (var line in lines)
        {
            var m = hostLine.Match(line);
            if (m.Success)
            {
                string host = m.Groups[1].Value.Trim().TrimEnd('.').ToLowerInvariant();
                if (host.StartsWith("www."))
                    host = host[4..];

                if (dangerous.Contains(host))
                    continue; // drop the line
            }

            kept.Add(line);
        }

        return string.Join("\r\n", kept);
    }

    /// <summary>
    /// Emergency / startup repair: purge Parental Shield hosts edits and DoH redirects,
    /// flush DNS only if the file actually changed. Safe to call when protection is off.
    /// </summary>
    public bool RepairDnsNow()
    {
        try
        {
            if (!File.Exists(_hostsPath))
            {
                _lastAppliedState = false;
                return true;
            }

            string current = File.ReadAllText(_hostsPath);
            string clean = SanitizeHostsContent(current);

            if (!HostsContentEquals(current, clean))
            {
                File.WriteAllText(_hostsPath, clean, HostsEncoding);
                FlushDns();
                App.LogDebug("RepairDnsNow: removed Parental Shield / DoH leftovers from hosts and flushed DNS");
            }
            else
            {
                App.LogDebug("RepairDnsNow: hosts already clean — no flush needed");
            }

            _lastAppliedState = false;
            return true;
        }
        catch (Exception ex)
        {
            App.LogDebug("RepairDnsNow error: " + ex.Message);
            return false;
        }
    }

    public bool HasManagedBlocksOrDangerousRedirects()
    {
        try
        {
            if (!File.Exists(_hostsPath)) return false;
            string current = File.ReadAllText(_hostsPath);
            string clean = SanitizeHostsContent(current);
            return !HostsContentEquals(current, clean);
        }
        catch
        {
            return false;
        }
    }

    private static bool HostsContentEquals(string a, string b)
    {
        static string Norm(string s)
        {
            if (s.Length > 0 && s[0] == '\uFEFF') s = s[1..];
            return s.Replace("\r\n", "\n").Replace('\r', '\n').TrimEnd() + "\n";
        }
        return string.Equals(Norm(a), Norm(b), StringComparison.Ordinal);
    }

    /// <summary>
    /// Applies or clears hosts rules based on whether a protected child session is active.
    /// Never rewrites or flushes DNS when the desired content is already in place.
    /// </summary>
    public bool SyncEnforcement(bool force = false)
    {
        bool shouldApply = _accountScope.ShouldEnforceNetworkBlocks();

        // When not enforcing, always prefer a clean hosts file (repairs leftovers even if state cache says "already off")
        if (!shouldApply)
        {
            bool ok = RestoreOriginalInternal();
            if (ok) _lastAppliedState = false;
            return ok;
        }

        if (!force && _lastAppliedState == true)
            return true;

        bool applied = ApplyBlockRulesInternal();
        if (applied) _lastAppliedState = true;
        return applied;
    }

    public bool ApplyBlockRules()
    {
        _lastAppliedState = null;
        return SyncEnforcement(force: true);
    }

    public bool RestoreOriginal()
    {
        _lastAppliedState = null;
        return RepairDnsNow();
    }

    private bool ApplyBlockRulesInternal()
    {
        try
        {
            string currentContent = File.Exists(_hostsPath) ? File.ReadAllText(_hostsPath) : "";
            string cleanContent = SanitizeHostsContent(currentContent);
            var domains = BuildDomainListForHosts();

            var sb = new StringBuilder();
            if (domains.Count > 0)
            {
                sb.AppendLine(BlockHeader);
                sb.AppendLine($"# Total active blocked domains: {domains.Count}");
                sb.AppendLine($"# Last updated: {DateTime.Now}");
                sb.AppendLine("# Site blocks only. Public DNS/DoH hostnames are NEVER redirected here.");

                foreach (var raw in domains)
                {
                    string d = raw.Replace("http://", "").Replace("https://", "").Split('/')[0].Trim().ToLowerInvariant();
                    if (string.IsNullOrWhiteSpace(d)) continue;

                    // Hard deny: never write DoH / public resolver hostnames into hosts
                    if (IsDangerousDnsHostname(d))
                        continue;

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

            string finalContent = cleanContent;
            if (sb.Length > 0)
                finalContent = cleanContent.TrimEnd() + "\r\n\r\n" + sb;

            if (HostsContentEquals(currentContent, finalContent))
            {
                App.LogDebug("Hosts already up to date — skipping write/flush");
                return true;
            }

            File.WriteAllText(_hostsPath, finalContent, HostsEncoding);
            FlushDns();
            App.LogDebug($"Hosts block rules applied ({domains.Count} domains)");
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

        // NOTE: DoH provider hostnames must NEVER go into the hosts file.
        // That was breaking internet DNS for the whole PC. Anti-DoH is browser-policy only.

        foreach (var custom in config.CustomWebsites)
        {
            if (custom.Enabled && !string.IsNullOrWhiteSpace(custom.Domain))
            {
                string d = custom.Domain.Trim();
                if (!IsDangerousDnsHostname(d))
                    set.Add(d);
            }
        }

        return [.. set];
    }

    private static bool IsDangerousDnsHostname(string domain)
    {
        string d = domain.Trim().ToLowerInvariant();
        if (d.StartsWith("www.")) d = d[4..];

        if (DefaultBlocklists.DoHProviders.Any(x => x.Equals(d, StringComparison.OrdinalIgnoreCase)))
            return true;

        return d is "one.one.one.one"
            or "1dot1dot1dot1.cloudflare-dns.com"
            or "dns.cloudflare.com"
            or "resolver1.opendns.com"
            or "resolver2.opendns.com"
            or "dns.google"
            or "dns.google.com";
    }

    private bool RestoreOriginalInternal()
    {
        // Same path as repair — only writes/flushes when something actually needs cleaning
        return RepairDnsNow();
    }
}
