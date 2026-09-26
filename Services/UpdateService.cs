using System;
using System.IO;
using System.Threading.Tasks;
using Velopack;
using Velopack.Sources;

namespace ParentalShield.Services;

public class UpdateService
{
    private readonly ConfigService? _configService;

    public UpdateService(ConfigService? configService = null)
    {
        _configService = configService;
    }

    private UpdateManager CreateUpdateManager()
    {
        return new UpdateManager(new GithubSource("https://github.com/amirthekingofficial/ParentalShield", null, false));
    }

    public async Task<UpdateInfo?> CheckForUpdatesAsync()
    {
        try
        {
            var mgr = CreateUpdateManager();
            if (!mgr.IsInstalled)
            {
                App.LogDebug("Velopack: App is running in portable/uninstalled dev mode.");
                return null;
            }

            App.LogDebug("Checking for updates via Velopack UpdateManager...");
            var updateInfo = await mgr.CheckForUpdatesAsync();
            return updateInfo;
        }
        catch (Exception ex)
        {
            App.LogDebug($"Update check failed: {ex.Message}");
            return null;
        }
    }

    public async Task DownloadUpdatesAsync(UpdateInfo update, Action<int>? progressCallback = null)
    {
        var mgr = CreateUpdateManager();
        App.LogDebug($"Downloading update {update.TargetFullRelease.Version}...");
        await mgr.DownloadUpdatesAsync(update, progressCallback);
    }

    public void ApplyUpdatesAndRestart(UpdateInfo update)
    {
        var mgr = CreateUpdateManager();
        App.LogDebug("Applying updates and restarting...");
        mgr.ApplyUpdatesAndRestart(update);
    }

    public async Task DownloadAndApplyUpdateAsync(UpdateInfo update, Action<int>? progressCallback = null)
    {
        await DownloadUpdatesAsync(update, progressCallback);
        ApplyUpdatesAndRestart(update);
    }
}
