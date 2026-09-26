using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

using Velopack;
using ParentalShield.Services;

namespace ParentalShield;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : System.Windows.Application
{
    public static bool IsStartupMinimized { get; set; } = false;

    protected override void OnStartup(StartupEventArgs e)
    {
        LogDebug("App OnStartup started");

        if (e.Args != null)
        {
            foreach (var arg in e.Args)
            {
                if (arg.Equals("--minimized", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("--silent", StringComparison.OrdinalIgnoreCase))
                {
                    IsStartupMinimized = true;
                    LogDebug("Startup mode: Minimized to tray");
                }
            }
        }

        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            LogCrash("AppDomain Unhandled", args.ExceptionObject as Exception);
        };

        DispatcherUnhandledException += (s, args) =>
        {
            LogCrash("Dispatcher Unhandled", args.Exception);
            args.Handled = true;
            MessageBox.Show($"Parental Shield encountered an unexpected error:\n\n{args.Exception.Message}\n\n{args.Exception.StackTrace}", "Parental Shield Error", MessageBoxButton.OK, MessageBoxImage.Error);
        };

        base.OnStartup(e);
        LogDebug("App OnStartup completed");
    }

    public static void LogDebug(string message)
    {
        try
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string dir = Path.Combine(appData, "ParentalShield");
            Directory.CreateDirectory(dir);
            string logPath = Path.Combine(dir, "debug.log");
            File.AppendAllText(logPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}\n");
        }
        catch
        {
        }
    }

    private static void LogCrash(string context, Exception? ex)
    {
        try
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string dir = Path.Combine(appData, "ParentalShield");
            Directory.CreateDirectory(dir);
            string logPath = Path.Combine(dir, "crash.log");
            File.AppendAllText(logPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{context}] {ex?.ToString()}\n\n");
            LogDebug($"CRASH [{context}]: {ex?.Message}");
        }
        catch
        {
        }
    }
}
