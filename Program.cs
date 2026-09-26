using System;
using Velopack;
using ParentalShield.Services;

namespace ParentalShield;

public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        // Velopack installer and auto-update lifecycle hooks
        VelopackApp.Build()
            .OnFirstRun((v) =>
            {
                AutostartService.SetEnabled(true);
            })
            .OnBeforeUninstallFastCallback((v) =>
            {
                AutostartService.SetEnabled(false);
            })
            .Run();

        // Check for startup flags
        if (args != null)
        {
            foreach (var arg in args)
            {
                if (arg.Equals("--minimized", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("--silent", StringComparison.OrdinalIgnoreCase))
                {
                    App.IsStartupMinimized = true;
                }
            }
        }

        var app = new App();
        app.InitializeComponent();
        app.Run();
    }
}
