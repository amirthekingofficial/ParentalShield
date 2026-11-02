using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace ParentalShield.Services;

/// <summary>
/// Periodically re-evaluates whether a protected child account is signed in and
/// applies or clears machine hosts / per-user browser policies accordingly.
/// Debounced so flaky session detection cannot flap hosts/DNS on and off.
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

    // Require several consecutive "child online" samples before turning hosts blocks ON.
    // Turning OFF is immediate so parent DNS is never left broken.
    private int _enforceOnStreak;
    private const int EnforceOnThreshold = 3;

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

        // Always scrub leftover DoH/hosts damage from older builds before doing anything else
        _browserPolicies.ClearMachineWideDoHPolicies();
        _hostsService.RepairDnsNow();

        _cts = new CancellationTokenSource();
        _loopTask = Task.Run(() => LoopAsync(_cts.Token));
        SyncNow(force: true);
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
            if (_configService.Config.TemporaryPauseUntilUtcTicks != null &&
                !_configService.Config.IsTemporarilyPaused())
            {
                _configService.Config.TemporaryPauseUntilUtcTicks = null;
                _configService.SaveConfig();
            }

            bool rawEnforce = _accountScope.ShouldEnforceNetworkBlocks();
            bool enforce = StabilizeEnforceDecision(rawEnforce, force);

            bool changed = enforce != _lastEnforce;

            // When idle / protection off: repair leftovers, do not keep rewriting hosts
            if (!enforce)
            {
                _hostsService.SyncEnforcement(force: false);
                _browserPolicies.SyncProtectedUserPolicies(false);
            }
            else
            {
                _hostsService.SyncEnforcement(force: force || changed);
                _browserPolicies.SyncProtectedUserPolicies(true);
            }

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
                    : "Enforcement OFF — hosts left clean for normal DNS");
                StateChanged?.Invoke();
            }
        }
        catch (Exception ex)
        {
            App.LogDebug("EnforcementService.SyncNow: " + ex.Message);
        }
    }

    private bool StabilizeEnforceDecision(bool rawEnforce, bool force)
    {
        // Master switch off / pause / no protected accounts → drop immediately
        if (!rawEnforce)
        {
            _enforceOnStreak = 0;
            return false;
        }

        // Forced sync from UI (user just enabled protection) — honor immediately
        if (force && _configService.Config.ProtectionActive)
        {
            // Still respect account scope: force only skips debounce when raw says ON
            _enforceOnStreak = EnforceOnThreshold;
            return true;
        }

        _enforceOnStreak++;
        if (_enforceOnStreak >= EnforceOnThreshold)
            return true;

        // Not enough consecutive positives — keep previous OFF state (or stay off)
        App.LogDebug($"Enforce debounce: child session probe {_enforceOnStreak}/{EnforceOnThreshold}");
        return _lastEnforce && rawEnforce;
    }

    private async Task LoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                // Never pass force here — periodic loop must not rewrite hosts unless state changes
                SyncNow(force: false);
            }
            catch (Exception ex)
            {
                App.LogDebug("Enforcement loop: " + ex.Message);
            }

            try
            {
                // Slower loop reduces DNS churn if anything still flaps
                await Task.Delay(8000, token);
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
        SyncNow(force: true);
    }

    public void ClearTemporaryPause()
    {
        _configService.Config.TemporaryPauseUntilUtcTicks = null;
        _configService.SaveConfig();
        SyncNow(force: true);
    }

    /// <summary>Parent-triggered emergency DNS repair (hosts + HKLM DoH leftovers).</summary>
    public void RepairDns()
    {
        _enforceOnStreak = 0;
        _lastEnforce = false;
        _browserPolicies.ClearMachineWideDoHPolicies();
        _hostsService.RepairDnsNow();
        _browserPolicies.SyncProtectedUserPolicies(false);
        StateChanged?.Invoke();
    }

    public void Dispose()
    {
        Stop();
        // On shutdown of the service object, leave hosts clean if we are not enforcing
        try
        {
            if (!_accountScope.ShouldEnforceNetworkBlocks())
                _hostsService.RepairDnsNow();
        }
        catch
        {
        }
        _cts?.Dispose();
    }
}
