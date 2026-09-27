using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;
using ParentalShield.Models;
using ParentalShield.Services;
using KeyEventArgs = System.Windows.Input.KeyEventArgs;
using Cursors = System.Windows.Input.Cursors;

namespace ParentalShield;

public partial class MainWindow : Wpf.Ui.Controls.FluentWindow
{
    private readonly ConfigService _configService;
    private readonly SecurityService _securityService;
    private readonly HostsService _hostsService;
    private readonly ProcessWatchdogService _watchdogService;
    private readonly UpdateService _updateService;
    private System.Windows.Forms.NotifyIcon? _notifyIcon;

    private string _currentPinInput = "";
    private Action? _pendingAction;
    private string _currentLogFilter = "all";
    private bool _isExplicitExit = false;

    public MainWindow()
    {
        App.LogDebug("MainWindow constructor started");
        InitializeComponent();
        App.LogDebug("MainWindow InitializeComponent finished");

        try
        {
            string iconPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "icon.ico");
            if (File.Exists(iconPath))
            {
                Icon = System.Windows.Media.Imaging.BitmapFrame.Create(new Uri(iconPath));
            }
        }
        catch (Exception ex)
        {
            App.LogDebug("Icon load exception: " + ex.Message);
        }

        _configService = new ConfigService();
        _securityService = new SecurityService(_configService);
        _hostsService = new HostsService(_configService);
        _watchdogService = new ProcessWatchdogService(_configService);
        _updateService = new UpdateService();

        // Subscribe to security lock state changes
        _securityService.LockStateChanged += OnLockStateChanged;

        // Subscribe to process watchdog events
        _watchdogService.ProcessBlocked += OnProcessBlocked;

        // Apply the native Windows 11 Mica backdrop & theme sync
        WindowBackdropType = Wpf.Ui.Controls.WindowBackdropType.Mica;
        Wpf.Ui.Appearance.SystemThemeWatcher.Watch(this);
        App.LogDebug("Native Windows 11 Mica backdrop applied");

        // Setup System Tray
        SetupSystemTray();
        App.LogDebug("SetupSystemTray completed");

        // Apply network hosts rules and start process monitoring
        if (_configService.Config.ProtectionActive)
        {
            _hostsService.ApplyBlockRules();
            _watchdogService.Start();
            App.LogDebug("Protection rules applied and watchdog started");
        }

        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
        KeyDown += MainWindow_KeyDown;
        App.LogDebug("MainWindow constructor completed");
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        App.LogDebug("MainWindow_Loaded fired");
        var helper = new System.Windows.Interop.WindowInteropHelper(this);
        App.LogDebug($"MainWindow HWND: 0x{helper.Handle.ToInt64():X}, Visibility: {Visibility}, State: {WindowState}");
        
        CheckAdminStatus();

        if (_configService.Config.StartWithWindows && !AutostartService.IsEnabled())
        {
            AutostartService.SetEnabled(true);
        }

        OnLockStateChanged(_securityService.IsUnlocked);
        RefreshUI();

        if (App.IsStartupMinimized)
        {
            Hide();
            _securityService.Lock();
            App.LogDebug("MainWindow_Loaded: Started silently minimized to tray on PC startup");
            return;
        }

        Activate();
        Topmost = true;
        Topmost = false;
        Focus();

        // If no passcode configured yet, show setup dialog immediately
        if (!_securityService.HasPasscode())
        {
            ShowSetupModal(isFirstRun: true);
            App.LogDebug("First run setup modal displayed");
        }
        App.LogDebug("MainWindow_Loaded completed");
    }

    public static bool IsAdministrator()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private void CheckAdminStatus()
    {
        bool isAdmin = IsAdministrator();
        if (isAdmin)
        {
            BannerElevationWarning.Visibility = Visibility.Collapsed;
            BadgeAdmin.BorderBrush = new SolidColorBrush(Color.FromArgb(0x40, 0x10, 0xB9, 0x81));
            BadgeAdminIcon.Fill = (Brush)FindResource("AccentSuccess");
            TxtAdminStatus.Text = "Administrator";
            TxtAdminStatus.Foreground = (Brush)FindResource("AccentSuccess");
        }
        else
        {
            BannerElevationWarning.Visibility = Visibility.Visible;
            BadgeAdmin.BorderBrush = new SolidColorBrush(Color.FromArgb(0x80, 0xF5, 0x9E, 0x0B));
            BadgeAdminIcon.Fill = (Brush)FindResource("AccentWarning");
            TxtAdminStatus.Text = "Enable Admin Mode";
            TxtAdminStatus.Foreground = (Brush)FindResource("AccentWarning");
        }
    }

    private void BtnElevate_Click(object sender, RoutedEventArgs e)
    {
        RelaunchAsAdministrator();
    }

    private void BadgeAdmin_Click(object sender, MouseButtonEventArgs e)
    {
        if (!IsAdministrator())
        {
            RelaunchAsAdministrator();
        }
    }

    private void RelaunchAsAdministrator()
    {
        try
        {
            string? exe = Environment.ProcessPath ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
            if (string.IsNullOrEmpty(exe)) return;

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = true,
                Verb = "runas"
            };
            System.Diagnostics.Process.Start(psi);
            _isExplicitExit = true;
            Application.Current.Shutdown();
        }
        catch (Exception ex)
        {
            ShowToast("Elevation cancelled or failed: " + ex.Message, "⚠️");
        }
    }

    private void SetupSystemTray()
    {
        try
        {
            string iconPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "icon.ico");
            var icon = File.Exists(iconPath) ? new System.Drawing.Icon(iconPath) : System.Drawing.SystemIcons.Shield;

            _notifyIcon = new System.Windows.Forms.NotifyIcon
            {
                Icon = icon,
                Text = "Parental Shield - Protection is on",
                Visible = true
            };

            var contextMenu = new System.Windows.Forms.ContextMenuStrip();
            contextMenu.Items.Add("Open Parental Shield", null, (s, e) => ShowAndRestoreWindow());
            contextMenu.Items.Add("Lock with PIN", null, (s, e) => {
                _securityService.Lock();
                ShowToast("Locked with PIN.", "🔒");
            });
            contextMenu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
            contextMenu.Items.Add("Turn off & Quit", null, (s, e) => RequestExitApplication());

            _notifyIcon.ContextMenuStrip = contextMenu;
            _notifyIcon.DoubleClick += (s, e) => ShowAndRestoreWindow();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Tray setup error: {ex.Message}");
        }
    }

    private void ShowAndRestoreWindow()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_isExplicitExit)
        {
            _watchdogService.Dispose();
            _notifyIcon?.Dispose();
            return;
        }

        if (_configService.Config.MinimizeToTray)
        {
            e.Cancel = true;
            Hide();
            // Automatically re-lock dashboard when minimized so children cannot restore and alter settings
            _securityService.Lock();
            _notifyIcon?.ShowBalloonTip(2500, "Parental Shield", "Running quietly in the background. Protection is still active.", System.Windows.Forms.ToolTipIcon.Info);
        }
    }



    // ==========================================================================
    // SECURITY & GATEKEEPER
    // ==========================================================================
    private void RequireParentAuth(Action action)
    {
        if (!_securityService.HasPasscode())
        {
            action();
            return;
        }

        if (_securityService.IsUnlocked)
        {
            action();
        }
        else
        {
            _pendingAction = action;
            ShowPasscodeModal();
        }
    }

    private void OnLockStateChanged(bool isUnlocked)
    {
        Dispatcher.Invoke(() =>
        {
            if (isUnlocked)
            {
                TxtLockIcon.Text = "🔓";
                TxtLockLabel.Text = "Parent Mode";
                TxtLockLabel.Foreground = (Brush)FindResource("AccentSuccess");
            }
            else
            {
                TxtLockIcon.Text = "🔒";
                TxtLockLabel.Text = "Locked";
                TxtLockLabel.Foreground = (Brush)FindResource("AccentDanger");
            }
        });
    }

    private void BtnLockStatus_Click(object sender, RoutedEventArgs e)
    {
        if (!_securityService.HasPasscode())
        {
            ShowSetupModal(isFirstRun: true);
        }
        else if (_securityService.IsUnlocked)
        {
            _securityService.Lock();
            ShowToast("Dashboard locked.", "🔒");
        }
        else
        {
            ShowPasscodeModal();
        }
    }

    private void ShowPasscodeModal()
    {
        _currentPinInput = "";
        UpdatePinDots();
        TxtPinError.Visibility = Visibility.Collapsed;
        ModalPasscode.Visibility = Visibility.Visible;
    }

    private void HidePasscodeModal()
    {
        ModalPasscode.Visibility = Visibility.Collapsed;
        _currentPinInput = "";
        _pendingAction = null;
        RefreshUI();
    }

    private void UpdatePinDots()
    {
        var activeBrush = (Brush)FindResource("SystemAccentColorPrimaryBrush");
        var inactiveBrush = (Brush)FindResource("CardStrokeColorDefaultBrush");

        PinDot0.Fill = _currentPinInput.Length > 0 ? activeBrush : Brushes.Transparent;
        PinDot0.Stroke = _currentPinInput.Length > 0 ? activeBrush : inactiveBrush;

        PinDot1.Fill = _currentPinInput.Length > 1 ? activeBrush : Brushes.Transparent;
        PinDot1.Stroke = _currentPinInput.Length > 1 ? activeBrush : inactiveBrush;

        PinDot2.Fill = _currentPinInput.Length > 2 ? activeBrush : Brushes.Transparent;
        PinDot2.Stroke = _currentPinInput.Length > 2 ? activeBrush : inactiveBrush;

        PinDot3.Fill = _currentPinInput.Length > 3 ? activeBrush : Brushes.Transparent;
        PinDot3.Stroke = _currentPinInput.Length > 3 ? activeBrush : inactiveBrush;
    }

    private void KeypadBtn_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string key)
        {
            HandlePinKey(key);
        }
    }

    private void MainWindow_KeyDown(object sender, KeyEventArgs e)
    {
        if (ModalPasscode.Visibility == Visibility.Visible)
        {
            if (e.Key >= Key.D0 && e.Key <= Key.D9)
            {
                HandlePinKey(((int)e.Key - (int)Key.D0).ToString());
            }
            else if (e.Key >= Key.NumPad0 && e.Key <= Key.NumPad9)
            {
                HandlePinKey(((int)e.Key - (int)Key.NumPad0).ToString());
            }
            else if (e.Key == Key.Back)
            {
                HandlePinKey("backspace");
            }
            else if (e.Key == Key.Escape)
            {
                HidePasscodeModal();
            }
        }
    }

    private void HandlePinKey(string key)
    {
        if (key == "clear")
        {
            _currentPinInput = "";
            UpdatePinDots();
            return;
        }

        if (key == "backspace")
        {
            if (_currentPinInput.Length > 0)
            {
                _currentPinInput = _currentPinInput[..^1];
                UpdatePinDots();
            }
            return;
        }

        if (_currentPinInput.Length < 8)
        {
            _currentPinInput += key;
            UpdatePinDots();

            if (_currentPinInput.Length >= 4)
            {
                bool success = _securityService.Unlock(_currentPinInput);
                if (success)
                {
                    HidePasscodeModal();
                    ShowToast("Parent Mode unlocked.", "🔓");

                    var action = _pendingAction;
                    _pendingAction = null;
                    action?.Invoke();
                }
                else
                {
                    TxtPinError.Visibility = Visibility.Visible;
                    _currentPinInput = "";
                    UpdatePinDots();
                }
            }
        }
    }

    private void BtnCancelPin_Click(object sender, RoutedEventArgs e) => HidePasscodeModal();

    private void BtnForgotPin_Click(object sender, RoutedEventArgs e)
    {
        HidePasscodeModal();
        string? q = _securityService.GetSecurityQuestion();
        if (string.IsNullOrEmpty(q))
        {
            ShowToast("No security question configured.", "⚠️");
            return;
        }

        TxtRecoveryQuestionPrompt.Text = q;
        TxtRecoveryAnswer.Text = "";
        PassRecoveryNew.Password = "";
        TxtRecoveryError.Visibility = Visibility.Collapsed;
        ModalRecovery.Visibility = Visibility.Visible;
    }

    // Setup / Change PIN
    private void ShowSetupModal(bool isFirstRun = false)
    {
        TxtSetupTitle.Text = isFirstRun ? "Welcome to Parental Shield" : "Change Parent Passcode";
        BtnCancelSetup.Visibility = isFirstRun ? Visibility.Collapsed : Visibility.Visible;
        PassSetupNew.Password = "";
        PassSetupConfirm.Password = "";
        TxtSetupAnswer.Text = "";
        TxtSetupError.Visibility = Visibility.Collapsed;
        ModalSetupPin.Visibility = Visibility.Visible;
    }

    private void BtnCancelSetup_Click(object sender, RoutedEventArgs e) => ModalSetupPin.Visibility = Visibility.Collapsed;

    private void BtnSaveSetup_Click(object sender, RoutedEventArgs e)
    {
        string p1 = PassSetupNew.Password.Trim();
        string p2 = PassSetupConfirm.Password.Trim();
        string q = (CmbSetupQuestion.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "What was the name of your first pet?";
        string a = TxtSetupAnswer.Text.Trim();

        if (p1.Length < 4)
        {
            TxtSetupError.Text = "PIN must be at least 4 digits.";
            TxtSetupError.Visibility = Visibility.Visible;
            return;
        }

        if (p1 != p2)
        {
            TxtSetupError.Text = "PINs do not match.";
            TxtSetupError.Visibility = Visibility.Visible;
            return;
        }

        if (string.IsNullOrEmpty(a))
        {
            TxtSetupError.Text = "Please provide an answer to the recovery question.";
            TxtSetupError.Visibility = Visibility.Visible;
            return;
        }

        _securityService.SetPasscode(p1, q, a);
        ModalSetupPin.Visibility = Visibility.Collapsed;
        _configService.AddLog("security", "Parent PIN", "Configured", "Parent passcode and recovery question configured.");
        ShowToast("Parent passcode successfully saved!", "🛡️");
        RefreshUI();
    }

    // Recovery
    private void BtnCancelRecovery_Click(object sender, RoutedEventArgs e) => ModalRecovery.Visibility = Visibility.Collapsed;

    private void BtnSubmitRecovery_Click(object sender, RoutedEventArgs e)
    {
        string a = TxtRecoveryAnswer.Text.Trim();
        string newPin = PassRecoveryNew.Password.Trim();

        if (string.IsNullOrEmpty(a))
        {
            TxtRecoveryError.Text = "Please enter your recovery answer.";
            TxtRecoveryError.Visibility = Visibility.Visible;
            return;
        }

        if (newPin.Length < 4)
        {
            TxtRecoveryError.Text = "New PIN must be at least 4 digits.";
            TxtRecoveryError.Visibility = Visibility.Visible;
            return;
        }

        bool ok = _securityService.VerifyRecovery(a, newPin);
        if (ok)
        {
            ModalRecovery.Visibility = Visibility.Collapsed;
            ShowToast("PIN reset successfully!", "✅");
            RefreshUI();
        }
        else
        {
            TxtRecoveryError.Text = "Incorrect answer to security question.";
            TxtRecoveryError.Visibility = Visibility.Visible;
        }
    }

    // ==========================================================================
    // REFRESH & STATE
    // ==========================================================================
    private void RefreshUI()
    {
        var config = _configService.Config;

        // Master switch and hero
        ToggleMasterProtection.IsChecked = config.ProtectionActive;
        UpdateHeroStatus(config.ProtectionActive);

        // Category switches
        ToggleAdultWeb.IsChecked = config.BlockAdultContent;
        ToggleGambling.IsChecked = config.BlockGambling;
        ToggleMatureApps.IsChecked = config.BlockMatureApps;
        ToggleMinimizeToTray.IsChecked = config.MinimizeToTray;
        ToggleStartWithWindows.IsChecked = AutostartService.IsEnabled();

        foreach (ComboBoxItem item in CmbAutoLockMinutes.Items)
        {
            if (item.Content is string s && s.StartsWith(config.AutoLockMinutes.ToString()))
            {
                CmbAutoLockMinutes.SelectedItem = item;
                break;
            }
        }

        // Counts
        int webCount = _hostsService.GetActiveDomains().Count;
        int appCount = _watchdogService.GetActiveBlockedProcessMap().Count;

        MetricWebsitesCount.Text = webCount.ToString();
        MetricAppsCount.Text = appCount.ToString();
        MetricInterceptsCount.Text = config.Stats.TotalBlocksIntercepted.ToString();

        // Lists
        RenderWebsitesList(TxtSearchWebsites.Text);
        RenderAppsList(TxtSearchApps.Text);
        RenderActivityLogs();
        RenderRecentDashboardLogs();

        TxtRecoveryQuestionStatus.Text = !string.IsNullOrEmpty(config.Security.Question)
            ? "Configured (Protected)"
            : "Not configured yet";
    }

    private void UpdateHeroStatus(bool active)
    {
        if (active)
        {
            MasterStatusDot.Fill = (Brush)FindResource("AccentSuccess");
            MasterStatusText.Text = "SHIELD ACTIVE";
            MasterStatusText.Foreground = (Brush)FindResource("AccentSuccess");
            MasterStatusPill.Background = new SolidColorBrush(Color.FromArgb(0x1A, 0x10, 0xB9, 0x81));
            MasterStatusPill.BorderBrush = new SolidColorBrush(Color.FromArgb(0x40, 0x10, 0xB9, 0x81));

            HeroShieldBorder.Background = new SolidColorBrush(Color.FromArgb(0x26, 0x10, 0xB9, 0x81));
            HeroShieldTitle.Text = "Protection is Active";
            HeroShieldSubtitle.Text = "System-wide 18+ adult web filtering & app termination enabled";
        }
        else
        {
            MasterStatusDot.Fill = (Brush)FindResource("AccentWarning");
            MasterStatusText.Text = "SHIELD PAUSED";
            MasterStatusText.Foreground = (Brush)FindResource("AccentWarning");
            MasterStatusPill.Background = new SolidColorBrush(Color.FromArgb(0x1A, 0xF5, 0x9E, 0x0B));
            MasterStatusPill.BorderBrush = new SolidColorBrush(Color.FromArgb(0x40, 0xF5, 0x9E, 0x0B));

            HeroShieldBorder.Background = new SolidColorBrush(Color.FromArgb(0x26, 0xF5, 0x9E, 0x0B));
            HeroShieldTitle.Text = "Protection is Paused";
            HeroShieldSubtitle.Text = "Restrictions are temporarily suspended";
        }
    }

    // ==========================================================================
    // NAVIGATION
    // ==========================================================================
    private void NavRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (PanelDashboard == null) return;

        PanelDashboard.Visibility = Visibility.Collapsed;
        PanelWebsites.Visibility = Visibility.Collapsed;
        PanelApps.Visibility = Visibility.Collapsed;
        PanelLogs.Visibility = Visibility.Collapsed;
        PanelSettings.Visibility = Visibility.Collapsed;

        if (NavDashboard.IsChecked == true) PanelDashboard.Visibility = Visibility.Visible;
        else if (NavWebsites.IsChecked == true) PanelWebsites.Visibility = Visibility.Visible;
        else if (NavApps.IsChecked == true) PanelApps.Visibility = Visibility.Visible;
        else if (NavLogs.IsChecked == true) PanelLogs.Visibility = Visibility.Visible;
        else if (NavSettings.IsChecked == true) PanelSettings.Visibility = Visibility.Visible;
    }

    private void BtnViewAllLogs_Click(object sender, RoutedEventArgs e)
    {
        NavLogs.IsChecked = true;
    }

    // ==========================================================================
    // DASHBOARD & CATEGORY TOGGLES
    // ==========================================================================
    private void ToggleMasterProtection_PreviewMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (!_securityService.HasPasscode() || _securityService.IsUnlocked) return;
        e.Handled = true;
        RequireParentAuth(() =>
        {
            ToggleMasterProtection.IsChecked = !ToggleMasterProtection.IsChecked;
            ApplyMasterProtectionToggle(ToggleMasterProtection.IsChecked == true);
        });
    }

    private void ToggleMasterProtection_Click(object sender, RoutedEventArgs e)
    {
        if (_securityService.HasPasscode() && !_securityService.IsUnlocked)
        {
            ToggleMasterProtection.IsChecked = _configService.Config.ProtectionActive;
            return;
        }

        ApplyMasterProtectionToggle(ToggleMasterProtection.IsChecked == true);
    }

    private void ApplyMasterProtectionToggle(bool target)
    {
        _configService.Config.ProtectionActive = target;
        _configService.SaveConfig();

        if (target)
        {
            _hostsService.ApplyBlockRules();
            _watchdogService.Start();
        }
        else
        {
            _hostsService.RestoreOriginal();
            _watchdogService.Stop();
        }

        RefreshUI();
        ShowToast(target ? "Parental Shield enabled." : "Parental Shield paused.", target ? "✅" : "⏸️");
    }

    private void ToggleCategory_PreviewMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (!_securityService.HasPasscode() || _securityService.IsUnlocked) return;
        e.Handled = true;
        if (sender is CheckBox chk)
        {
            RequireParentAuth(() =>
            {
                chk.IsChecked = !chk.IsChecked;
                ApplyCategoryToggles();
            });
        }
    }

    private void ToggleCategory_Click(object sender, RoutedEventArgs e)
    {
        if (_securityService.HasPasscode() && !_securityService.IsUnlocked)
        {
            RefreshUI();
            return;
        }

        ApplyCategoryToggles();
    }

    private void ApplyCategoryToggles()
    {
        _configService.Config.BlockAdultContent = ToggleAdultWeb.IsChecked == true;
        _configService.Config.BlockGambling = ToggleGambling.IsChecked == true;
        _configService.Config.BlockMatureApps = ToggleMatureApps.IsChecked == true;
        _configService.SaveConfig();

        _hostsService.ApplyBlockRules();
        RefreshUI();
        ShowToast("Category filters updated.", "✅");
    }

    // ==========================================================================
    // WEBSITES TAB
    // ==========================================================================
    private void RenderWebsitesList(string query)
    {
        ListCustomWebsites.Items.Clear();
        query = query.Trim().ToLowerInvariant();

        var list = _configService.Config.CustomWebsites
            .Where(w => string.IsNullOrEmpty(query) || w.Domain.Contains(query, StringComparison.OrdinalIgnoreCase) || w.Category.Contains(query, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (list.Count == 0)
        {
            ListCustomWebsites.Items.Add(new TextBlock
            {
                Text = string.IsNullOrEmpty(query) ? "No custom blocked websites added yet." : "No matching websites found.",
                Foreground = (Brush)FindResource("TextFillColorTertiaryBrush"),
                Margin = new Thickness(10)
            });
            return;
        }

        foreach (var item in list)
        {
            var card = CreateWebsiteCard(item);
            ListCustomWebsites.Items.Add(card);
        }
    }

    private Border CreateWebsiteCard(BlockedWebsite site)
    {
        var border = new Border
        {
            Background = (Brush)FindResource("ControlFillColorDefaultBrush"),
            BorderBrush = (Brush)FindResource("CardStrokeColorDefaultBrush"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(14, 10, 14, 10),
            Margin = new Thickness(0, 0, 0, 8)
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var sp = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        var title = new TextBlock { Text = site.Domain, FontSize = 13.5, FontWeight = FontWeights.SemiBold, Foreground = (Brush)FindResource("TextFillColorPrimaryBrush") };
        var sub = new TextBlock { Text = $"{site.Category} • Added {site.AddedAt:d}", FontSize = 11.5, Foreground = (Brush)FindResource("TextFillColorTertiaryBrush"), Margin = new Thickness(0, 2, 0, 0) };
        sp.Children.Add(title);
        sp.Children.Add(sub);
        Grid.SetColumn(sp, 0);

        var rightSp = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        var chk = new CheckBox { IsChecked = site.Enabled, Cursor = Cursors.Hand, Margin = new Thickness(0, 0, 14, 0), VerticalAlignment = VerticalAlignment.Center };
        chk.PreviewMouseLeftButtonDown += (s, e) =>
        {
            if (!_securityService.HasPasscode() || _securityService.IsUnlocked) return;
            e.Handled = true;
            RequireParentAuth(() =>
            {
                chk.IsChecked = !chk.IsChecked;
                site.Enabled = chk.IsChecked == true;
                _configService.SaveConfig();
                _hostsService.ApplyBlockRules();
                RefreshUI();
            });
        };
        chk.Click += (s, e) =>
        {
            if (_securityService.HasPasscode() && !_securityService.IsUnlocked)
            {
                RefreshUI();
                return;
            }
            site.Enabled = chk.IsChecked == true;
            _configService.SaveConfig();
            _hostsService.ApplyBlockRules();
            RefreshUI();
        };

        var btnDel = new Button
        {
            Content = "🗑️",
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand,
            FontSize = 13
        };
        btnDel.Click += (s, e) =>
        {
            RequireParentAuth(() =>
            {
                _configService.Config.CustomWebsites.Remove(site);
                _configService.SaveConfig();
                _hostsService.ApplyBlockRules();
                _configService.AddLog("website", site.Domain, "Domain Removed", $"Removed {site.Domain} from blocklist.");
                RefreshUI();
                ShowToast($"Removed {site.Domain}", "ℹ️");
            });
        };

        rightSp.Children.Add(chk);
        rightSp.Children.Add(btnDel);
        Grid.SetColumn(rightSp, 1);

        grid.Children.Add(sp);
        grid.Children.Add(rightSp);
        border.Child = grid;
        return border;
    }

    private void BtnAddWebsite_Click(object sender, RoutedEventArgs e)
    {
        string raw = TxtNewDomain.Text.Trim();
        string cat = (CmbNewDomainCategory.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Custom Block";
        AddWebsite(raw, cat);
    }

    private void TxtNewDomain_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            BtnAddWebsite_Click(sender, e);
        }
    }

    private void QuickAddSite_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string tag)
        {
            var parts = tag.Split('|');
            AddWebsite(parts[0], parts.Length > 1 ? parts[1] : "Custom Block");
        }
    }

    private void AddWebsite(string rawDomain, string category)
    {
        string d = rawDomain.Replace("http://", "").Replace("https://", "").Split('/')[0].Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(d) || !d.Contains('.'))
        {
            ShowToast("Please enter a valid domain (e.g. example.com).", "⚠️");
            return;
        }

        RequireParentAuth(() =>
        {
            if (_configService.Config.CustomWebsites.Any(w => w.Domain.Equals(d, StringComparison.OrdinalIgnoreCase)))
            {
                ShowToast("Domain is already in your blocklist.", "⚠️");
                return;
            }

            _configService.Config.CustomWebsites.Add(new BlockedWebsite
            {
                Domain = d,
                Category = category,
                Enabled = true,
                AddedAt = DateTime.Now
            });

            _configService.SaveConfig();
            _hostsService.ApplyBlockRules();
            _configService.AddLog("website", d, "Domain Added", $"Added {d} to blocked websites.");

            TxtNewDomain.Text = "";
            RefreshUI();
            ShowToast($"Website '{d}' blocked across all browsers.", "✅");
        });
    }

    private void TxtSearchWebsites_TextChanged(object sender, TextChangedEventArgs e)
    {
        RenderWebsitesList(TxtSearchWebsites.Text);
    }

    // ==========================================================================
    // APPLICATIONS TAB
    // ==========================================================================
    private void RenderAppsList(string query)
    {
        ListBlockedApps.Items.Clear();
        query = query.Trim().ToLowerInvariant();

        // Default mature apps section
        if (_configService.Config.BlockMatureApps)
        {
            var defaults = DefaultBlocklists.DefaultMatureApps
                .Where(a => string.IsNullOrEmpty(query) || a.Name.Contains(query, StringComparison.OrdinalIgnoreCase) || a.ProcessName.Contains(query, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (defaults.Count > 0)
            {
                ListBlockedApps.Items.Add(new TextBlock
                {
                    Text = "BUILT-IN PROTECTED APPLICATIONS",
                    FontSize = 11,
                    FontWeight = FontWeights.Bold,
                    Foreground = (Brush)FindResource("TextFillColorTertiaryBrush"),
                    Margin = new Thickness(4, 4, 0, 8)
                });

                foreach (var app in defaults)
                {
                    ListBlockedApps.Items.Add(CreateDefaultAppCard(app));
                }
            }
        }

        // Custom blocked apps section
        var custom = _configService.Config.CustomApps
            .Where(a => string.IsNullOrEmpty(query) || a.Name.Contains(query, StringComparison.OrdinalIgnoreCase) || a.ProcessName.Contains(query, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (custom.Count > 0)
        {
            ListBlockedApps.Items.Add(new TextBlock
            {
                Text = "CUSTOM BLOCKED APPLICATIONS",
                FontSize = 11,
                FontWeight = FontWeights.Bold,
                Foreground = (Brush)FindResource("TextFillColorTertiaryBrush"),
                Margin = new Thickness(4, 14, 0, 8)
            });

            foreach (var app in custom)
            {
                ListBlockedApps.Items.Add(CreateCustomAppCard(app));
            }
        }
    }

    private Border CreateDefaultAppCard(BlockedApp app)
    {
        var border = new Border
        {
            Background = (Brush)FindResource("ControlFillColorDefaultBrush"),
            BorderBrush = (Brush)FindResource("CardStrokeColorDefaultBrush"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(14, 10, 14, 10),
            Margin = new Thickness(0, 0, 0, 8)
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var sp = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        var titleSp = new StackPanel { Orientation = Orientation.Horizontal };
        titleSp.Children.Add(new TextBlock { Text = app.Name, FontSize = 13.5, FontWeight = FontWeights.SemiBold, Foreground = (Brush)FindResource("TextFillColorPrimaryBrush") });
        titleSp.Children.Add(new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(0x26, 0xEF, 0x44, 0x44)),
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(6, 1, 6, 1),
            Margin = new Thickness(8, 0, 0, 0),
            Child = new TextBlock { Text = "Built-in", FontSize = 10, FontWeight = FontWeights.Bold, Foreground = (Brush)FindResource("AccentDanger") }
        });
        sp.Children.Add(titleSp);
        sp.Children.Add(new TextBlock { Text = $"{app.ProcessName} • {app.Category}", FontSize = 11.5, Foreground = (Brush)FindResource("TextFillColorTertiaryBrush"), Margin = new Thickness(0, 2, 0, 0) });
        Grid.SetColumn(sp, 0);

        var badge = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(0x26, 0x10, 0xB9, 0x81)),
            CornerRadius = new CornerRadius(6),
            Padding = new Thickness(8, 4, 8, 4),
            VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock { Text = "Active Watchdog", FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = (Brush)FindResource("AccentSuccess") }
        };
        Grid.SetColumn(badge, 1);

        grid.Children.Add(sp);
        grid.Children.Add(badge);
        border.Child = grid;
        return border;
    }

    private Border CreateCustomAppCard(BlockedApp app)
    {
        var border = new Border
        {
            Background = (Brush)FindResource("ControlFillColorDefaultBrush"),
            BorderBrush = (Brush)FindResource("CardStrokeColorDefaultBrush"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(14, 10, 14, 10),
            Margin = new Thickness(0, 0, 0, 8)
        };

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var sp = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        sp.Children.Add(new TextBlock { Text = app.Name, FontSize = 13.5, FontWeight = FontWeights.SemiBold, Foreground = (Brush)FindResource("TextFillColorPrimaryBrush") });
        sp.Children.Add(new TextBlock { Text = $"{app.ProcessName} • {app.Category}", FontSize = 11.5, Foreground = (Brush)FindResource("TextFillColorTertiaryBrush"), Margin = new Thickness(0, 2, 0, 0) });
        Grid.SetColumn(sp, 0);

        var rightSp = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        var chk = new CheckBox { IsChecked = app.Enabled, Cursor = Cursors.Hand, Margin = new Thickness(0, 0, 14, 0), VerticalAlignment = VerticalAlignment.Center };
        chk.PreviewMouseLeftButtonDown += (s, e) =>
        {
            if (!_securityService.HasPasscode() || _securityService.IsUnlocked) return;
            e.Handled = true;
            RequireParentAuth(() =>
            {
                chk.IsChecked = !chk.IsChecked;
                app.Enabled = chk.IsChecked == true;
                _configService.SaveConfig();
                if (app.Enabled) _watchdogService.CheckAndTerminateBlockedProcesses();
                RefreshUI();
            });
        };
        chk.Click += (s, e) =>
        {
            if (_securityService.HasPasscode() && !_securityService.IsUnlocked)
            {
                RefreshUI();
                return;
            }
            app.Enabled = chk.IsChecked == true;
            _configService.SaveConfig();
            if (app.Enabled) _watchdogService.CheckAndTerminateBlockedProcesses();
            RefreshUI();
        };

        var btnDel = new Button
        {
            Content = "🗑️",
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand,
            FontSize = 13
        };
        btnDel.Click += (s, e) =>
        {
            RequireParentAuth(() =>
            {
                _configService.Config.CustomApps.Remove(app);
                _configService.SaveConfig();
                _configService.AddLog("app", app.Name, "App Removed", $"Removed {app.Name} ({app.ProcessName}) from blocked apps.");
                RefreshUI();
                ShowToast($"Removed {app.Name}", "ℹ️");
            });
        };

        rightSp.Children.Add(chk);
        rightSp.Children.Add(btnDel);
        Grid.SetColumn(rightSp, 1);

        grid.Children.Add(sp);
        grid.Children.Add(rightSp);
        border.Child = grid;
        return border;
    }

    private void BtnAddApp_Click(object sender, RoutedEventArgs e)
    {
        string name = TxtNewAppName.Text.Trim();
        string proc = TxtNewAppProcess.Text.Trim();
        string cat = (CmbNewAppCategory.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Custom Application";
        AddApp(name, proc, cat);
    }

    private void TxtNewAppProcess_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            BtnAddApp_Click(sender, e);
        }
    }

    private void QuickAddApp_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string tag)
        {
            var parts = tag.Split('|');
            AddApp(parts[0], parts[1], parts.Length > 2 ? parts[2] : "Custom Application");
        }
    }

    private void AddApp(string name, string rawProcess, string category)
    {
        string proc = rawProcess.Trim();
        if (string.IsNullOrWhiteSpace(proc))
        {
            ShowToast("Process executable name is required.", "⚠️");
            return;
        }

        if (!proc.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            proc += ".exe";
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            name = System.IO.Path.GetFileNameWithoutExtension(proc);
        }

        RequireParentAuth(() =>
        {
            if (_configService.Config.CustomApps.Any(a => a.ProcessName.Equals(proc, StringComparison.OrdinalIgnoreCase)))
            {
                ShowToast("Application is already in your blocklist.", "⚠️");
                return;
            }

            _configService.Config.CustomApps.Add(new BlockedApp
            {
                Name = name,
                ProcessName = proc,
                Category = category,
                Enabled = true,
                AddedAt = DateTime.Now
            });

            _configService.SaveConfig();
            _watchdogService.CheckAndTerminateBlockedProcesses();
            _configService.AddLog("app", name, "App Added", $"Added {name} ({proc}) to blocked apps.");

            TxtNewAppName.Text = "";
            TxtNewAppProcess.Text = "";
            RefreshUI();
            ShowToast($"Blocked application '{name}'.", "✅");
        });
    }

    private void TxtSearchApps_TextChanged(object sender, TextChangedEventArgs e)
    {
        RenderAppsList(TxtSearchApps.Text);
    }

    private void BtnBrowseExe_Click(object sender, RoutedEventArgs e)
    {
        RequireParentAuth(() =>
        {
            var dlg = new OpenFileDialog
            {
                Title = "Select Application Executable to Prohibit",
                Filter = "Executables (*.exe)|*.exe|All Files (*.*)|*.*"
            };

            if (dlg.ShowDialog() == true)
            {
                string fn = System.IO.Path.GetFileName(dlg.FileName);
                string friendly = System.IO.Path.GetFileNameWithoutExtension(dlg.FileName);
                TxtNewAppName.Text = friendly;
                TxtNewAppProcess.Text = fn;
                AddApp(friendly, fn, "Custom Application");
            }
        });
    }

    // Running Apps Scanner
    private void BtnScanRunningApps_Click(object sender, RoutedEventArgs e)
    {
        ModalRunningApps.Visibility = Visibility.Visible;
        TxtFilterRunningApps.Text = "";
        RefreshRunningAppsList();
    }

    private void BtnCloseRunningApps_Click(object sender, RoutedEventArgs e) => ModalRunningApps.Visibility = Visibility.Collapsed;
    private void BtnRefreshRunningApps_Click(object sender, RoutedEventArgs e) => RefreshRunningAppsList();
    private void TxtFilterRunningApps_TextChanged(object sender, TextChangedEventArgs e) => RefreshRunningAppsList();

    private void RefreshRunningAppsList()
    {
        ListRunningAppsScanner.Items.Clear();
        string q = TxtFilterRunningApps.Text.Trim().ToLowerInvariant();

        var apps = ProcessWatchdogService.GetRunningUserApplications()
            .Where(a => string.IsNullOrEmpty(q) || a.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase) || a.MainWindowTitle.Contains(q, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (apps.Count == 0)
        {
            ListRunningAppsScanner.Items.Add(new TextBlock { Text = "No running user programs found.", Foreground = (Brush)FindResource("TextFillColorTertiaryBrush"), Margin = new Thickness(10) });
            return;
        }

        foreach (var app in apps)
        {
            var border = new Border
            {
                Background = (Brush)FindResource("ControlFillColorDefaultBrush"),
                BorderBrush = (Brush)FindResource("CardStrokeColorDefaultBrush"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(12, 8, 12, 8),
                Margin = new Thickness(0, 0, 0, 6)
            };

            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            var sp = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            sp.Children.Add(new TextBlock { Text = app.ProcessName, FontWeight = FontWeights.SemiBold, FontSize = 13, Foreground = (Brush)FindResource("TextFillColorPrimaryBrush") });
            string meta = $"{app.InstanceCount} process{(app.InstanceCount > 1 ? "es" : "")} • {app.MemoryUsage}";
            if (!string.IsNullOrEmpty(app.MainWindowTitle)) meta += $" • \"{app.MainWindowTitle}\"";
            sp.Children.Add(new TextBlock { Text = meta, FontSize = 11, Foreground = (Brush)FindResource("TextFillColorTertiaryBrush") });
            Grid.SetColumn(sp, 0);

            var btn = new Button { Content = "+ Block", Style = (Style)FindResource("OutlineButtonStyle"), Height = 30, Padding = new Thickness(10, 0, 10, 0), FontSize = 12 };
            btn.Click += (s, e) =>
            {
                ModalRunningApps.Visibility = Visibility.Collapsed;
                AddApp(System.IO.Path.GetFileNameWithoutExtension(app.ProcessName), app.ProcessName, "Prohibited Program");
            };
            Grid.SetColumn(btn, 1);

            grid.Children.Add(sp);
            grid.Children.Add(btn);
            border.Child = grid;
            ListRunningAppsScanner.Items.Add(border);
        }
    }

    // ==========================================================================
    // ACTIVITY LOGS
    // ==========================================================================
    private void RenderActivityLogs()
    {
        ListActivityLogs.ItemsSource = null;
        var logs = _configService.Logs;

        if (_currentLogFilter != "all")
        {
            logs = logs.Where(l => l.Type.Equals(_currentLogFilter, StringComparison.OrdinalIgnoreCase)).ToList();
        }

        ListActivityLogs.ItemsSource = logs;
    }

    private void RenderRecentDashboardLogs()
    {
        ListDashboardRecentLogs.Items.Clear();
        var recent = _configService.Logs.Take(6).ToList();

        if (recent.Count == 0)
        {
            ListDashboardRecentLogs.Items.Add(new TextBlock
            {
                Text = "No prohibited attempts recorded yet.",
                Foreground = (Brush)FindResource("TextFillColorTertiaryBrush"),
                Margin = new Thickness(10)
            });
            return;
        }

        foreach (var l in recent)
        {
            var sp = new StackPanel { Margin = new Thickness(0, 4, 0, 8) };
            var grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            string targetDisplay = string.IsNullOrWhiteSpace(l.Target) ? "(Prohibited Application)" : l.Target;
            var title = new TextBlock { Text = targetDisplay, FontWeight = FontWeights.SemiBold, FontSize = 13, Foreground = (Brush)FindResource("TextFillColorPrimaryBrush") };
            var time = new TextBlock { Text = $"{l.Timestamp:HH:mm:ss}", FontSize = 11, Foreground = (Brush)FindResource("TextFillColorTertiaryBrush") };
            Grid.SetColumn(title, 0);
            Grid.SetColumn(time, 1);
            grid.Children.Add(title);
            grid.Children.Add(time);

            string detailDisplay = string.IsNullOrWhiteSpace(l.Details) ? "Attempt intercepted and blocked by Parental Shield" : l.Details;
            var detail = new TextBlock { Text = detailDisplay, FontSize = 11.5, Foreground = (Brush)FindResource("TextFillColorTertiaryBrush"), Margin = new Thickness(0, 2, 0, 0) };
            sp.Children.Add(grid);
            sp.Children.Add(detail);
            ListDashboardRecentLogs.Items.Add(sp);
        }
    }

    private void FilterLogs_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string tag)
        {
            _currentLogFilter = tag;
            RenderActivityLogs();
        }
    }

    private void BtnClearLogs_Click(object sender, RoutedEventArgs e)
    {
        RequireParentAuth(() =>
        {
            _configService.ClearLogs();
            RefreshUI();
            ShowToast("Activity log cleared.", "🗑️");
        });
    }

    private void OnProcessBlocked(ActivityLogEntry log, BlockedApp app)
    {
        Dispatcher.Invoke(() =>
        {
            RefreshUI();
            ShowToast($"Blocked {app.Name}", "🛑");
            _notifyIcon?.ShowBalloonTip(3000, "App Blocked", $"Closed \"{app.Name}\" because it's on your blocked list.", System.Windows.Forms.ToolTipIcon.Info);
        });
    }

    // ==========================================================================
    // SETTINGS TAB
    // ==========================================================================
    private void BtnChangePin_Click(object sender, RoutedEventArgs e)
    {
        RequireParentAuth(() => ShowSetupModal(isFirstRun: false));
    }

    private void BtnChangeRecovery_Click(object sender, RoutedEventArgs e)
    {
        RequireParentAuth(() => ShowSetupModal(isFirstRun: false));
    }

    private void CmbAutoLockMinutes_PreviewMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (!_securityService.HasPasscode() || _securityService.IsUnlocked) return;
        e.Handled = true;
        RequireParentAuth(() =>
        {
            CmbAutoLockMinutes.IsDropDownOpen = true;
        });
    }

    private void CmbAutoLockMinutes_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (CmbAutoLockMinutes.SelectedItem is ComboBoxItem item && item.Content is string text)
        {
            int mins = text.StartsWith("10") ? 10 : text.StartsWith("5") ? 5 : text.StartsWith("1") ? 1 : 3;
            if (_configService != null)
            {
                _configService.Config.AutoLockMinutes = mins;
                _configService.SaveConfig();
                _securityService?.ResetAutoLockTimer();
            }
        }
    }

    private void ToggleMinimizeToTray_PreviewMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (!_securityService.HasPasscode() || _securityService.IsUnlocked) return;
        e.Handled = true;
        RequireParentAuth(() =>
        {
            ToggleMinimizeToTray.IsChecked = !ToggleMinimizeToTray.IsChecked;
            _configService.Config.MinimizeToTray = ToggleMinimizeToTray.IsChecked == true;
            _configService.SaveConfig();
            RefreshUI();
        });
    }

    private void ToggleMinimizeToTray_Click(object sender, RoutedEventArgs e)
    {
        if (_securityService.HasPasscode() && !_securityService.IsUnlocked)
        {
            RefreshUI();
            return;
        }

        _configService.Config.MinimizeToTray = ToggleMinimizeToTray.IsChecked == true;
        _configService.SaveConfig();
    }

    private void ToggleStartWithWindows_PreviewMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (!_securityService.HasPasscode() || _securityService.IsUnlocked) return;
        e.Handled = true;
        RequireParentAuth(() =>
        {
            ToggleStartWithWindows.IsChecked = !ToggleStartWithWindows.IsChecked;
            bool enable = ToggleStartWithWindows.IsChecked == true;
            AutostartService.SetEnabled(enable);
            _configService.Config.StartWithWindows = enable;
            _configService.SaveConfig();
            RefreshUI();
            ShowToast(enable ? "Parental Shield will start with Windows." : "Removed from Windows startup.", enable ? "🚀" : "ℹ️");
        });
    }

    private void ToggleStartWithWindows_Click(object sender, RoutedEventArgs e)
    {
        if (_securityService.HasPasscode() && !_securityService.IsUnlocked)
        {
            RefreshUI();
            return;
        }

        bool enable = ToggleStartWithWindows.IsChecked == true;
        AutostartService.SetEnabled(enable);
        _configService.Config.StartWithWindows = enable;
        _configService.SaveConfig();
        ShowToast(enable ? "Parental Shield will start with Windows." : "Removed from Windows startup.", enable ? "🚀" : "ℹ️");
    }

    private async void BtnCheckUpdates_Click(object sender, RoutedEventArgs e)
    {
        BtnCheckUpdates.IsEnabled = false;
        TxtUpdateStatus.Text = "Checking for updates...";
        ShowToast("Checking for updates...", "🔄");

        try
        {
            var updateInfo = await _updateService.CheckForUpdatesAsync();
            if (updateInfo != null)
            {
                TxtUpdateStatus.Text = $"Update ready: v{updateInfo.TargetFullRelease.Version}";
                var result = MessageBox.Show(
                    $"A new update (v{updateInfo.TargetFullRelease.Version}) is available.\n\nWould you like to download and install it now?",
                    "Update Available",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information);

                if (result == MessageBoxResult.Yes)
                {
                    TxtUpdateStatus.Text = "Downloading update...";
                    ShowToast("Downloading update...", "⬇️");
                    await _updateService.DownloadUpdatesAsync(updateInfo);
                    TxtUpdateStatus.Text = "Applying update...";
                    _updateService.ApplyUpdatesAndRestart(updateInfo);
                }
                else
                {
                    TxtUpdateStatus.Text = "Update postponed";
                }
            }
            else
            {
                TxtUpdateStatus.Text = "You have the latest version.";
                ShowToast("Parental Shield is up to date.", "✅");
            }
        }
        catch (Exception ex)
        {
            TxtUpdateStatus.Text = "Check completed";
            App.LogDebug("Update check exception: " + ex.Message);
            ShowToast("You're on the latest installed version.", "✅");
        }
        finally
        {
            BtnCheckUpdates.IsEnabled = true;
        }
    }

    private void BtnExitApp_Click(object sender, RoutedEventArgs e)
    {
        RequestExitApplication();
    }

    private void RequestExitApplication()
    {
        RequireParentAuth(() =>
        {
            _isExplicitExit = true;
            Close();
            Application.Current.Shutdown();
        });
    }

    // ==========================================================================
    // TOAST NOTIFICATIONS
    // ==========================================================================
    private DispatcherTimer? _toastTimer;

    private void ShowToast(string message, string icon = "🛡️")
    {
        ToastIcon.Text = icon;
        ToastText.Text = message;
        ToastNotification.Visibility = Visibility.Visible;

        _toastTimer?.Stop();
        _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3.5) };
        _toastTimer.Tick += (s, e) =>
        {
            ToastNotification.Visibility = Visibility.Collapsed;
            _toastTimer.Stop();
        };
        _toastTimer.Start();
    }
}