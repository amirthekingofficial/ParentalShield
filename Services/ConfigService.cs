using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using ParentalShield.Models;

namespace ParentalShield.Services;

public class ConfigService
{
    private readonly string _configDir;
    private readonly string _configFile;
    private readonly string _logsFile;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public AppConfig Config { get; private set; }
    public List<ActivityLogEntry> Logs { get; private set; } = new();

    public ConfigService()
    {
        // Machine-wide config so parent settings apply no matter which account launches the app.
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        _configDir = Path.Combine(programData, "ParentalShield");
        _configFile = Path.Combine(_configDir, "config.json");
        _logsFile = Path.Combine(_configDir, "activity_logs.json");

        EnsureDirectory();
        MigrateFromPerUserAppDataIfNeeded();
        Config = LoadConfig();
        Logs = LoadLogs();
    }

    private void EnsureDirectory()
    {
        if (!Directory.Exists(_configDir))
        {
            Directory.CreateDirectory(_configDir);
        }
    }

    /// <summary>
    /// Older builds stored config under the parent's %AppData%. Copy once into ProgramData
    /// so Fast User Switching / other accounts share the same rules.
    /// </summary>
    private void MigrateFromPerUserAppDataIfNeeded()
    {
        try
        {
            if (File.Exists(_configFile)) return;

            string legacyDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "ParentalShield");
            string legacyConfig = Path.Combine(legacyDir, "config.json");
            string legacyLogs = Path.Combine(legacyDir, "activity_logs.json");

            if (File.Exists(legacyConfig))
            {
                File.Copy(legacyConfig, _configFile, overwrite: false);
                App.LogDebug("Migrated config.json from AppData to ProgramData");
            }

            if (File.Exists(legacyLogs) && !File.Exists(_logsFile))
            {
                File.Copy(legacyLogs, _logsFile, overwrite: false);
            }
        }
        catch (Exception ex)
        {
            App.LogDebug("Config migration notice: " + ex.Message);
        }
    }

    public string ConfigDir => _configDir;

    private AppConfig LoadConfig()
    {
        try
        {
            if (File.Exists(_configFile))
            {
                string json = File.ReadAllText(_configFile);
                var loaded = JsonSerializer.Deserialize<AppConfig>(json);
                if (loaded != null) return loaded;
            }
        }
        catch (Exception ex)
        {
            App.LogDebug($"Error loading config: {ex.Message}");
        }
        return new AppConfig();
    }

    public void SaveConfig()
    {
        try
        {
            EnsureDirectory();
            string json = JsonSerializer.Serialize(Config, JsonOptions);
            File.WriteAllText(_configFile, json);
        }
        catch (Exception ex)
        {
            App.LogDebug($"Error saving config: {ex.Message}");
        }
    }

    private List<ActivityLogEntry> LoadLogs()
    {
        try
        {
            if (File.Exists(_logsFile))
            {
                string json = File.ReadAllText(_logsFile);
                var logs = JsonSerializer.Deserialize<List<ActivityLogEntry>>(json);
                if (logs != null) return logs;
            }
        }
        catch
        {
        }
        return new List<ActivityLogEntry>();
    }

    private void SaveLogs()
    {
        try
        {
            EnsureDirectory();
            if (Logs.Count > 300)
            {
                Logs = Logs.GetRange(0, 300);
            }
            string json = JsonSerializer.Serialize(Logs, JsonOptions);
            File.WriteAllText(_logsFile, json);
        }
        catch
        {
        }
    }

    public ActivityLogEntry AddLog(string type, string target, string action, string details)
    {
        var entry = new ActivityLogEntry
        {
            Type = type,
            Target = target,
            Action = action,
            Details = details,
            Timestamp = DateTime.Now
        };

        Logs.Insert(0, entry);
        SaveLogs();

        if (type == "app")
        {
            Config.Stats.AppsBlockedCount++;
            Config.Stats.TotalBlocksIntercepted++;
        }
        else if (type == "website")
        {
            Config.Stats.WebsitesBlockedCount++;
            Config.Stats.TotalBlocksIntercepted++;
        }

        SaveConfig();
        return entry;
    }

    public void ClearLogs()
    {
        Logs.Clear();
        SaveLogs();
    }
}
