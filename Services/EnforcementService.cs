using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using ParentalShield.Models;

namespace ParentalShield.Services;

/// <summary>
/// Periodically re-evaluates whether a protected child account is signed in and
/// applies or clears machine hosts / per-user browser policies accordingly.
/// This is what keeps parent-account DNS intact when kids are logged off.
/// </summary>
public class EnforcementService : IDisposable
{
    private readonly ConfigService _configService;
    private readonly AccountScopeService _accountScope;
    private readonly HostsService _hostsService;
    private readonly BrowserPolicyService _browserPolicies;
    private readonly ProcessWatchdogService _watchdog;

    private CancellationTokenSource? _cts;
    private Task? _loopTask;
    private bool _lastEnforce;

    public event Action? StateChanged;

    public bool IsCurrentlyEnforcing => _lastEnforce;

    public EnforcementService(
        ConfigService configService,
        AccountScopeService accountScope,
        HostsService hostsService,
        BrowserPolicyService browserPolicies,
        ProcessWatchdogService watchdog)
    {
        _configService = configService;
        _accountScope = accountScope;
        _hostsService = hostsService;
        _browserPolicies = browserPolicies;
        _watchdog = watchdog;
    }

    public void Start()
    {
        if (_loopTask != null) return;

        // One-time cleanup of legacy machine-wide DoH registry policies
        _browserPolicies.ClearMachineWideDoHPolicies();

        _cts = new CancellationTokenSource();
        _loopTask = Task.Run(() => LoopAsync(_cts.Token));
        SyncNow();
    }

    public void Stop()
    {
        _cts?.Cancel();
        _loopTask = null;
    }

    public void SyncNow(bool force = false)
    {
        try
        {
            // Expire temporary pause if needed
            if (_configService.Config.TemporaryPauseUntilUtcTicks != null &&
                !_configService.Config.IsTemporarilyPaused())
            {
                _configService.Config.TemporaryPauseUntilUtcTicks = null;
                _configService.SaveConfig();
            }

            bool enforce = _accountScope.ShouldEnforceNetworkBlocks();
            bool changed = enforce != _lastEnforce;

            // force=true when settings change so hosts domain lists refresh even if scope state is unchanged
            _hostsService.SyncEnforcement(force: force || changed);
            _browserPolicies.SyncProtectedUserPolicies(enforce);

            if (enforce)
            {
                _watchdog.Start();
                if (_accountScope.IsBedtimeNow() &&
                    _configService.Config.Bedtime.CloseBrowsersDuringBedtime)
                {
                    CloseBrowsersForProtectedUsers();
                }
            }
            else
            {
                // Keep watchdog running so we can still scope-check; it no-ops for non-protected owners
                if (_configService.Config.ProtectionActive && !_configService.Config.IsTemporarilyPaused())
                    _watchdog.Start();
                else
                    _watchdog.Stop();
            }

            _lastEnforce = enforce;
            if (changed)
            {
                App.LogDebug(enforce
                    ? "Enforcement ON — protected child session active"
                    : "Enforcement OFF — hosts cleared for other accounts' DNS");
                StateChanged?.Invoke();
            }
        }
        catch (Exception ex)
        {
            App.LogDebug("EnforcementService.SyncNow: " + ex.Message);
        }
    }

    private async Task LoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                SyncNow();
            }
            catch (Exception ex)
            {
                App.LogDebug("Enforcement loop: " + ex.Message);
            }

            try
            {
                await Task.Delay(4000, token);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }
    }

    private void CloseBrowsersForProtectedUsers()
    {
        string[] browsers =
        [
            "chrome", "msedge", "firefox", "brave", "opera", "iexplore", "chromium"
        ];

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                string name = proc.ProcessName.ToLowerInvariant();
                if (Array.IndexOf(browsers, name) < 0) continue;

                string? owner = AccountScopeService.TryGetProcessOwner(proc);
                if (_accountScope.ShouldEnforceAgainstUser(owner))
                {
                    proc.Kill(entireProcessTree: true);
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
    }

    public void PauseForMinutes(int minutes)
    {
        _configService.Config.TemporaryPauseUntilUtcTicks =
            DateTime.UtcNow.AddMinutes(Math.Max(1, minutes)).Ticks;
        _configService.SaveConfig();
        SyncNow();
    }

    public void ClearTemporaryPause()
    {
        _configService.Config.TemporaryPauseUntilUtcTicks = null;
        _configService.SaveConfig();
        SyncNow();
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
    }
}
