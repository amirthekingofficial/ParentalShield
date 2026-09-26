using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using Microsoft.Win32;

namespace ParentalShield.Services;

public static class AutostartService
{
    private const string TaskName = "ParentalShieldAutostart";
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string AppName = "ParentalShield";

    public static bool IsAdministrator()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    public static bool IsEnabled()
    {
        return IsTaskEnabled() || IsRegistryEnabled();
    }

    private static bool IsRegistryEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, false);
            return key?.GetValue(AppName) != null;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsTaskEnabled()
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = $"/query /tn \"{TaskName}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            proc.Start();
            proc.WaitForExit(2000);
            return proc.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public static void SetEnabled(bool enable)
    {
        string exePath = Environment.ProcessPath 
            ?? Process.GetCurrentProcess().MainModule?.FileName 
            ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ParentalShield.exe");

        if (enable)
        {
            // If running with administrator privileges, register Scheduled Task with /rl highest
            // This allows the app to start at boot with full Admin rights WITHOUT any UAC prompt!
            if (IsAdministrator())
            {
                bool taskCreated = CreateElevatedTask(exePath);
                if (taskCreated)
                {
                    RemoveRegistryRunKey();
                    App.LogDebug($"Elevated Scheduled Task autostart enabled: \"{exePath}\"");
                    return;
                }
            }

            // Fallback to registry run key
            SetRegistryRunKey(exePath);
        }
        else
        {
            RemoveElevatedTask();
            RemoveRegistryRunKey();
            App.LogDebug("Autostart disabled");
        }
    }

    private static bool CreateElevatedTask(string exePath)
    {
        try
        {
            // /sc onlogon: run at user logon
            // /rl highest: run with Administrator privileges without triggering a UAC prompt
            // /f: force create/overwrite
            string args = $"/create /tn \"{TaskName}\" /tr \"\\\"{exePath}\\\" --minimized\" /sc onlogon /rl highest /f";
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = args,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            proc.Start();
            proc.WaitForExit(3000);
            return proc.ExitCode == 0;
        }
        catch (Exception ex)
        {
            App.LogDebug("Failed to create elevated scheduled task: " + ex.Message);
            return false;
        }
    }

    private static void RemoveElevatedTask()
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "schtasks.exe",
                    Arguments = $"/delete /tn \"{TaskName}\" /f",
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                }
            };
            proc.Start();
            proc.WaitForExit(2000);
        }
        catch (Exception ex)
        {
            App.LogDebug("Failed to delete scheduled task: " + ex.Message);
        }
    }

    private static void SetRegistryRunKey(string exePath)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, true);
            key?.SetValue(AppName, $"\"{exePath}\" --minimized");
            App.LogDebug($"Registry autostart enabled: \"{exePath}\"");
        }
        catch (Exception ex)
        {
            App.LogDebug($"Failed to update autostart registry key: {ex.Message}");
        }
    }

    private static void RemoveRegistryRunKey()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, true);
            key?.DeleteValue(AppName, false);
        }
        catch { }
    }
}
