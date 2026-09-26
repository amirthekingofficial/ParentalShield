using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace ParentalShield.Services;

public class HostsService
{
    private const string BlockHeader = "# === PARENTAL SHIELD MANAGED BLOCKS (DO NOT MODIFY) ===";
    private const string BlockFooter = "# === END PARENTAL SHIELD MANAGED BLOCKS ===";
    private readonly string _hostsPath;
    private readonly string _backupPath;
    private readonly ConfigService _configService;

    // Win32 API for instantaneous DNS resolver cache flush
    [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache", SetLastError = true)]
    private static extern int DnsFlushResolverCache();

    public HostsService(ConfigService configService)
    {
        _configService = configService;
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
            Console.WriteLine($"Backup error: {ex.Message}");
        }
    }

    public List<string> GetActiveDomains()
    {
        var config = _configService.Config;
        if (!config.ProtectionActive) return [];

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

        foreach (var doh in DefaultBlocklists.DoHProviders)
        {
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
            // 1. Instant Win32 API flush
            DnsFlushResolverCache();
        }
        catch
        {
        }

        try
        {
            // 2. Supplemental ipconfig flush with hidden process
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

    public void DisableBrowserDoH()
    {
        try
        {
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", "off");
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", "off");
            Registry.SetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode", "off");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Registry DoH policy notice: {ex.Message}");
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

    public bool ApplyBlockRules()
    {
        try
        {
            string currentContent = File.Exists(_hostsPath) ? File.ReadAllText(_hostsPath) : "";
            string cleanContent = CleanHostsText(currentContent);
            var domains = GetActiveDomains();

            var sb = new StringBuilder();
            if (domains.Count > 0)
            {
                sb.AppendLine(BlockHeader);
                sb.AppendLine($"# Total active blocked domains: {domains.Count}");
                sb.AppendLine($"# Last updated: {DateTime.Now}");

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
            DisableBrowserDoH();
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error applying block rules to hosts: {ex.Message}");
            return false;
        }
    }

    public bool RestoreOriginal()
    {
        try
        {
            if (File.Exists(_hostsPath))
            {
                string currentContent = File.ReadAllText(_hostsPath);
                string cleanContent = CleanHostsText(currentContent);
                File.WriteAllText(_hostsPath, cleanContent, Encoding.UTF8);
                FlushDns();
            }
            return true;
        }
        catch
        {
            return false;
        }
    }
}
