using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ParentalShield.Models;

namespace ParentalShield.Services;

public class RunningAppInfo
{
    public string ProcessName { get; set; } = string.Empty;
    public string MainWindowTitle { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string MemoryUsage { get; set; } = string.Empty;
    public int InstanceCount { get; set; } = 1;
}

public class ProcessWatchdogService : IDisposable
{
    private readonly ConfigService _configService;
    private CancellationTokenSource? _cts;
    private Task? _watchdogTask;
    private readonly Dictionary<string, DateTime> _recentlyKilled = new(StringComparer.OrdinalIgnoreCase);

    public event Action<ActivityLogEntry, BlockedApp>? ProcessBlocked;

    public ProcessWatchdogService(ConfigService configService)
    {
        _configService = configService;
    }

    public void Start()
    {
        if (_watchdogTask != null) return;
        _cts = new CancellationTokenSource();
        _watchdogTask = Task.Run(() => WatchdogLoopAsync(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        _watchdogTask = null;
    }

    private async Task WatchdogLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                CheckAndTerminateBlockedProcesses();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Watchdog error: {ex.Message}");
            }

            try
            {
                await Task.Delay(1200, token);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }
    }

    public Dictionary<string, BlockedApp> GetActiveBlockedProcessMap()
    {
        var map = new Dictionary<string, BlockedApp>(StringComparer.OrdinalIgnoreCase);
        var config = _configService.Config;
        if (!config.ProtectionActive) return map;

        // 1. Default 18+ / mature apps
        if (config.BlockMatureApps)
        {
            foreach (var app in DefaultBlocklists.DefaultMatureApps)
            {
                string key = NormalizeProcessName(app.ProcessName);
                if (!map.ContainsKey(key))
                {
                    map[key] = app;
                }
            }
        }

        // 2. Custom enabled apps
        foreach (var app in config.CustomApps)
        {
            if (app.Enabled && !string.IsNullOrWhiteSpace(app.ProcessName))
            {
                string key = NormalizeProcessName(app.ProcessName);
                map[key] = app;
            }
        }

        return map;
    }

    private static string NormalizeProcessName(string proc)
    {
        string name = Path.GetFileNameWithoutExtension(proc.Trim());
        return name.ToLowerInvariant();
    }

    public void CheckAndTerminateBlockedProcesses()
    {
        var blockedMap = GetActiveBlockedProcessMap();
        if (blockedMap.Count == 0) return;

        var running = Process.GetProcesses();
        var now = DateTime.Now;

        foreach (var proc in running)
        {
            try
            {
                string name = proc.ProcessName.ToLowerInvariant();
                if (blockedMap.TryGetValue(name, out var meta))
                {
                    // Kill immediately
                    proc.Kill(entireProcessTree: true);

                    // Debounce logs & alert to once every 5 seconds per process
                    if (!_recentlyKilled.TryGetValue(name, out var lastTime) || (now - lastTime).TotalSeconds > 5)
                    {
                        _recentlyKilled[name] = now;

                        var log = _configService.AddLog(
                            "app",
                            meta.Name,
                            "Terminated",
                            $"Blocked attempt to launch prohibited app: {meta.Name} ({meta.ProcessName})"
                        );

                        ProcessBlocked?.Invoke(log, meta);
                    }
                }
            }
            catch
            {
                // Process may have already exited or system-restricted
            }
            finally
            {
                proc.Dispose();
            }
        }
    }

    public static List<RunningAppInfo> GetRunningUserApplications()
    {
        var ignored = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "system", "smss", "csrss", "wininit", "services", "lsass", "svchost",
            "fontdrvhost", "dwm", "memory compression", "spoolsv", "registry",
            "conhost", "sihost", "taskhostw", "explorer", "ctfmon", "smartscreen",
            "runtimebroker", "shellexperiencehost", "startmenuexperiencehost",
            "searchhost", "lockapp", "applicationframehost", "dllhost", "wudfhost",
            "parentalshield", "devenv", "idle"
        };

        var map = new Dictionary<string, RunningAppInfo>(StringComparer.OrdinalIgnoreCase);

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                string name = proc.ProcessName;
                if (ignored.Contains(name)) continue;

                long memMb = proc.WorkingSet64 / (1024 * 1024);
                string memStr = $"{memMb} MB";
                string title = proc.MainWindowTitle;

                if (!map.TryGetValue(name, out var item))
                {
                    map[name] = new RunningAppInfo
                    {
                        ProcessName = name + ".exe",
                        ProcessId = proc.Id,
                        MainWindowTitle = title,
                        MemoryUsage = memStr,
                        InstanceCount = 1
                    };
                }
                else
                {
                    item.InstanceCount++;
                    if (string.IsNullOrEmpty(item.MainWindowTitle) && !string.IsNullOrEmpty(title))
                    {
                        item.MainWindowTitle = title;
                    }
                }
            }
            catch
            {
            }
            finally
            {
                proc.Dispose();
            }
        }

        return [.. map.Values.OrderBy(a => a.ProcessName)];
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
    }
}
