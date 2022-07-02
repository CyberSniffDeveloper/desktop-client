using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using CyberSniff.Classes;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using CyberSniff.Views;
using MaterialDesignThemes.Wpf;
using Microsoft.Win32;
using PacketDotNet;
using SharpPcap;
using SharpPcap.Npcap;
using WpfAnimatedGif;
using static CyberSniff.Extensions;
using Label = CyberSniff.Models.Label;
using Settings = CyberSniff.Views.Settings;
using Theme = CyberSniff.Models.Theme;

namespace CyberSniff.Windows;

[Obfuscation(Feature = "apply to member * when constructor: virtualization", Exclude = false)]
public partial class MainWindow : Window
{
    public static readonly RoutedUICommand AnalyseCommand =
        new("Analyse", "AnalyseCommand", typeof(MainWindow));

    public static readonly RoutedUICommand ClearAllCommand =
        new("Clear", "ClearAllCommand", typeof(MainWindow));

    public static readonly RoutedUICommand CopyCommand =
        new("Copy", "CopyCommand", typeof(MainWindow));

    public static readonly RoutedUICommand ExportCommand =
        new("Export", "ExportCommand", typeof(MainWindow));

    public static readonly RoutedUICommand ExportTheme =
        new("Export", "ExportTheme", typeof(MainWindow));

    public static readonly RoutedUICommand HandleCaptions =
        new("Handle captions", "HandleCaptions", typeof(MainWindow));

    public static readonly RoutedUICommand HideSideView =
        new("Hide side view", "HideSideView", typeof(MainWindow));

    public static readonly RoutedUICommand HideNotification =
        new("Hide notification", "HideNotification", typeof(MainWindow));

    public static readonly RoutedUICommand ImportTheme =
        new("Import", "ImportTheme", typeof(MainWindow));

    public static readonly DependencyProperty IsDialogOpenProperty =
        DependencyProperty.Register("IsDialogOpen", typeof(bool),
            typeof(Window), new UIPropertyMetadata(false));

    public static readonly DependencyProperty IsSniffingProperty =
        DependencyProperty.Register("IsSniffing", typeof(bool),
            typeof(Window), new UIPropertyMetadata(false));

    public static readonly RoutedUICommand LabelCommand =
        new("Add to labels", "LabelCommand", typeof(MainWindow));

    public static readonly RoutedUICommand LocateCommand =
        new("Locate", "LocateCommand", typeof(MainWindow));

    public static readonly RoutedUICommand OpenAdapter =
        new("Open adapter", "OpenAdapter", typeof(MainWindow));

    public static readonly RoutedUICommand OpenArp =
        new("Open Arp", "OpenArp", typeof(MainWindow));

    public static readonly RoutedUICommand OpenFilters =
        new("Open filters", "OpenFilters", typeof(MainWindow));

    public static readonly RoutedUICommand OpenLog =
        new("Open log", "OpenLog", typeof(MainWindow));

    public static readonly RoutedUICommand OpenSettings =
        new("Open settings", "OpenSettings", typeof(MainWindow));

    public static readonly RoutedUICommand OpenXbox =
        new("Open Xbox", "OpenXbox", typeof(MainWindow));

    public static readonly RoutedUICommand RefreshAdaptersCommand =
        new("Refresh", "RefreshAdaptersCommand", typeof(MainWindow));

    public static readonly RoutedUICommand RemoveAtCommand =
        new("Remove", "RemoveAtCommand", typeof(MainWindow));

    public static readonly RoutedUICommand ResetBackground =
        new("Reset", "ResetBackground", typeof(MainWindow));

    public static readonly RoutedUICommand SetBackground =
        new("Browse", "SetBackground", typeof(MainWindow));

    public static readonly RoutedUICommand SettingsLoadHandler =
        new("Load", "SettingsLoadHandler", typeof(MainWindow));

    public static readonly RoutedUICommand TcpProbeCommand =
        new("Probe", "TcpProbeCommand", typeof(MainWindow));

    public static readonly RoutedUICommand ToggleCapture =
        new("Toggle capture", "ToggleCapture", typeof(MainWindow));

    public static readonly RoutedUICommand TogglePanelCommand =
        new("Toggle", "TogglePanelCommand", typeof(MainWindow));

    private readonly DispatcherTimer authTask = new();

    public BitmapImage BackgroundCache;

    private readonly List<int> blacklistedPorts = new();

    private readonly BindingList<CaptureGrid> dataSource = new();

    private readonly TimeSpan lastStatisticsInterval = new(0, 0, 1);

    private readonly object queueLock = new();

    private PacketAnalyserWindow analyserWindow;

    private Dictionary<IPAddress, Packet> analyserData = new();

    private ArpDevice arpDevices;

    private Thread arpThread;

    private bool arpThreadStop;

    private PacketArrivalEventHandler arrivalEventHandler;

    private Thread backgroundThread;

    private bool backgroundThreadStop;

    private List<IPAddress> blacklistedAddresses = new();

    private ICaptureStatistics captureStatistics;

    private CaptureStoppedEventHandler captureStoppedEventHandler;

    private bool closeStoryBoardCompleted;

    private object currentView;

    private string currentWallpaper = "None";

    private ICaptureDevice device;

    private List<IPAddress> ipAddresses = new();

    private bool isControlPanelOpen = true;

    private bool isPoisoning;

    private DateTime lastStatisticsOutput;

    private bool isNotificationOpen;

    private bool isNotificationQueued;

    private int packetCount;

    private List<RawCapture> packetQueue = new();

    private Queue<PacketWrapper> packetStrings;

    private bool settingsView;

    private bool statisticsUiNeedsUpdate;

    public MainWindow()
    {
        try
        {
            InitializeComponent();

            MainDataGrid.ItemsSource = dataSource;

            dataSource.AddingNew += DataSource_AddingNew;
            dataSource.RaiseListChangedEvents = true;
            dataSource.ListChanged += DataSource_ListChanged;
            ResetTitle();

            Title = "I'm ashamed that you're actually using this";

            Initialize();

            CommandBindings.Add(new CommandBinding(SettingsLoadHandler, SettingsLoadHandlerEvent));
            CommandBindings.Add(new CommandBinding(SetBackground, SetBackgroundEvent));
            CommandBindings.Add(new CommandBinding(ResetBackground, ResetBackgroundEvent));
            CommandBindings.Add(new CommandBinding(ExportTheme, ExportThemeEvent));
            CommandBindings.Add(new CommandBinding(ImportTheme, ImportThemeEvent));
            CommandBindings.Add(new CommandBinding(OpenLog, OpenLogEvent));
            CommandBindings.Add(new CommandBinding(ToggleCapture, ToggleCaptureEvent));
            CommandBindings.Add(new CommandBinding(OpenSettings, OpenSettingsEvent));
            CommandBindings.Add(new CommandBinding(HideSideView, HideSideViewEvent));
            CommandBindings.Add(new CommandBinding(HandleCaptions, HandleCaptionsEvent));
            CommandBindings.Add(new CommandBinding(OpenFilters, OpenFiltersEvent));
            CommandBindings.Add(new CommandBinding(OpenAdapter, OpenAdapterEvent));
            CommandBindings.Add(new CommandBinding(OpenArp, OpenArpEvent));
            CommandBindings.Add(new CommandBinding(TogglePanelCommand, TogglePanelEvent));
            CommandBindings.Add(new CommandBinding(CopyCommand, CopyMenuItemEvent));
            CommandBindings.Add(new CommandBinding(LocateCommand, LocateMenuItemEvent));
            CommandBindings.Add(new CommandBinding(TcpProbeCommand, TcpProbeMenuItemEvent));
            CommandBindings.Add(new CommandBinding(ExportCommand, ExportMenuItemEvent));
            CommandBindings.Add(new CommandBinding(ClearAllCommand, ClearAllMenuItemEvent));
            ;
            CommandBindings.Add(new CommandBinding(RemoveAtCommand, RemoveAtMenuItemEvent));
            CommandBindings.Add(new CommandBinding(AnalyseCommand, AnalyseMenuItemEvent));
            CommandBindings.Add(new CommandBinding(LabelCommand, AddToLabelsMenuItemEvent));
            CommandBindings.Add(new CommandBinding(RefreshAdaptersCommand, RefreshAdaptersEvent));
            CommandBindings.Add(new CommandBinding(HideNotification, HideNotificationEvent));
        }
        catch (Exception e)
        {
            _ = e.AutoDumpExceptionAsync();
            Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
            {
                Icon = MsgBox.MsgBoxIcon.Error, Button = MsgBox.MsgBoxBtn.Ok,
                Message = $"{Properties.Resources.GENERIC_EXCEPTION}\n\nWhat happened: {e.Message}"
            });
            Environment.Exit(1);
        }
    }

    public bool IsDialogOpen
    {
        get => (bool) GetValue(IsDialogOpenProperty);
        set => SetValue(IsDialogOpenProperty, value);
    }

    public bool IsSniffing
    {
        get => (bool) GetValue(IsSniffingProperty);
        set => SetValue(IsSniffingProperty, value);
    }

    private void HideNotificationEvent(object sender, ExecutedRoutedEventArgs e)
    {
        var sb = FindResource("CloseNotif") as BeginStoryboard;
        sb?.Storyboard.Begin();
        isNotificationQueued = false;
        isNotificationOpen = false;
    }

    private void AddToLabelsMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj) return;

        TextHost.Text = dgObj.IpAddress.ToString();
        TextLabel.Text = dgObj.Label;
        IsDialogOpen = true;
    }

    private async void AddToSource(CaptureGrid dgObject)
    {
        try
        {
            if (ipAddresses == null) return;
            if (ipAddresses.Contains(dgObject.IpAddress)) return;

            ipAddresses.Add(dgObject.IpAddress);
            dataSource.Add(dgObject);
        }
        catch (Exception e)
        {
            await e.AutoDumpExceptionAsync();
        }
    }

    private async void AnalyseMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem == null || MainDataGrid.SelectedItem is not CaptureGrid selectedItem) return;

        try
        {
            await Dispatcher.InvokeAsync(() =>
            {
                var openDev = GetCurrentCaptureDevice();
                try
                {
                    openDev.Open();
                    if (!analyserData.ContainsKey(selectedItem.IpAddress)) return;

                    analyserWindow = new PacketAnalyserWindow(analyserData[selectedItem.IpAddress],
                        BackgroundCache, GetCurrentCaptureDevice().MacAddress)
                    {
                        Owner = this,
                        Topmost = Globals.Settings.TopMost
                    };
                    DimScreen();
                    analyserWindow.Closed += GenericToolWindow_Closed;
                    analyserWindow.ShowDialog();
                }
                finally
                {
                    openDev.Close();
                }
            });
        }
        catch (Exception er)
        {
            await er.AutoDumpExceptionAsync();
            Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
            {
                Icon = MsgBox.MsgBoxIcon.Error, Button = MsgBox.MsgBoxBtn.Ok,
                Message = $"{Properties.Resources.EXCEPTION_BASIC}\n\nWhat happened: {er.Message}"
            });
        }
    }

    private async void ArpThread()
    {
        try
        {
            var targetLocalAddress = IPAddress.Parse("0.0.0.0");
            var targetPhysicalAddress = PhysicalAddress.Parse("00-00-00-00-00-00");
            var sourceLocalAddress = IPAddress.Parse("0.0.0.0");
            var sourcePhysicalAddress = PhysicalAddress.Parse("00-00-00-00-00-00");
            await Dispatcher.InvokeAsync(() =>
            {
                targetLocalAddress = arpDevices.TargetLocalAddress;
                targetPhysicalAddress = arpDevices.TargetPhysicalAddress;
                sourceLocalAddress = arpDevices.SourceLocalAddress;
                sourcePhysicalAddress = arpDevices.SourcePhysicalAddress;
            });
            while (!arpThreadStop && device != null)
            {
                await Task.Delay(1000);
                NpcapDevice currDevice = null;

                await Dispatcher.InvokeAsync(() => { currDevice = (NpcapDevice) GetCurrentCaptureDevice(); });
                await currDevice.PoisonAsync(targetLocalAddress, targetPhysicalAddress, sourceLocalAddress,
                    sourcePhysicalAddress);
            }
        }
        catch (Exception e)
        {
            await e.AutoDumpExceptionAsync();
            await Dispatcher.InvokeAsync(() =>
            {
                ShowNotification(NotificationType.Alert,
                    "ARP thread has thrown an exception, check the error log for more details");
            });
        }
    }

    private async void BackgroundThread()
    {
        while (!backgroundThreadStop)
        {
            var shouldSleep = true;

            lock (queueLock)
            {
                if (packetQueue.Count != 0) shouldSleep = false;
            }

            if (shouldSleep)
            {
                await Task.Delay(250);
            }
            else
            {
                List<RawCapture> ourQueue;
                lock (queueLock)
                {
                    ourQueue = packetQueue;
                    packetQueue = new List<RawCapture>();
                }

                foreach (var packetWrapper in ourQueue.Select(packet => new PacketWrapper(packetCount, packet)))
                {
                    await Dispatcher.InvokeAsync(() => { packetStrings.Enqueue(packetWrapper); });
                    packetCount++;

                    PacketParser(packetWrapper);
                }

                if (!statisticsUiNeedsUpdate) continue;

                UpdateCaptureStatistics();
                statisticsUiNeedsUpdate = false;
            }
        }
    }

    private void ChangeSideView(Page page, string title)
    {
        currentView = page;
        SideViewFrame.Navigate(page);
        SideViewTitle.Text = title;
    }

    private void ClearAllMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.Items.Count <= 0) return;

        ipAddresses = new List<IPAddress>();
        dataSource.Clear();
        ShowNotification(NotificationType.Info, Properties.Resources.UI_CLEAR_SUCCESS);
    }

    private void CopyMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem == null || e.OriginalSource is not DataGridCell dgCell) return;
        
        if (dgCell.Content is ContentPresenter presenter && presenter.Content is CaptureGrid captureGrid)
            captureGrid.IpAddress.ToString().CopyToClipboard();
    }

    private void DataGridView_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
    }

    private async void DataSource_AddingNew(object sender, AddingNewEventArgs e)
    {
        try
        {
            var isGeolocationEnabled = Globals.Settings.Geolocate;
            var flag = Globals.Settings.ShowFlags;
            if (!isGeolocationEnabled) return;
            {
                var gridObject = new CaptureGrid();
                _ = Task.Run(async () =>
                {
                    var resp = await Web.IpLocationAsync(gridObject.IpAddress);
                    if (resp is null)
                    {
                        gridObject.Country = "N/A";
                        gridObject.City = "N/A";
                        gridObject.Isp = "N/A";
                        gridObject.State = "N/A";
                        gridObject.DDoSProtected = PackIconKind.None;
                        return;
                    }

                    if (flag)
                        gridObject.Flag =
                            $"pack://application:,,,/CyberSniff;Component/Resources/Images/Flags/{resp.Country.Replace(' ', '-')}.png";
                    gridObject.Country = resp.Country;
                    gridObject.City = resp.City;
                    gridObject.Isp = resp.Isp;
                    gridObject.State = resp.Region;
                    gridObject.DDoSProtected = PackIconKind.LockOpenOutline;
                    if (resp.IsProxy || resp.IsHosting || resp.IsHotspot)
                        gridObject.DDoSProtected = PackIconKind.LockOutline;
                    await Dispatcher.InvokeAsync(() => { e.NewObject = gridObject; });
                });
            }
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void DataSource_ListChanged(object sender, ListChangedEventArgs e)
    {
        if (e.ListChangedType != ListChangedType.ItemAdded) return;

        try
        {
            var isGeolocationEnabled = Globals.Settings.Geolocate;
            var flag = Globals.Settings.ShowFlags;
            if (!isGeolocationEnabled) return;
            if (dataSource[e.NewIndex] is var gridObject)
                if (string.IsNullOrWhiteSpace(gridObject.Country))
                    _ = Task.Run(async () =>
                    {
                        var resp = await Web.IpLocationAsync(gridObject.IpAddress);
                        if (resp is null)
                        {
                            gridObject.Country = "N/A";
                            gridObject.City = "N/A";
                            gridObject.Isp = "N/A";
                            gridObject.State = "N/A";
                            gridObject.DDoSProtected = PackIconKind.None;
                            dataSource[e.NewIndex] = gridObject;
                            return;
                        }

                        if (flag)
                            gridObject.Flag =
                                $"pack://application:,,,/CyberSniff;Component/Resources/Images/Flags/{resp.Country.Replace(' ', '-')}.png";
                        gridObject.Country = resp.Country;
                        gridObject.City = resp.City;
                        gridObject.Isp = resp.Isp;
                        gridObject.State = resp.Region;
                        gridObject.DDoSProtected = PackIconKind.None;
                        if (resp.IsProxy || resp.IsHosting || resp.IsHotspot)
                            gridObject.DDoSProtected = PackIconKind.LockOutline;

                        dataSource[e.NewIndex] = gridObject;
                        await Dispatcher.InvokeAsync(() => { dataSource.ResetBindings(); });
                    });
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
            ShowNotification(NotificationType.Error,
                "Something went wrong whilst handling a data source change. It has been written to the log file");
        }
    }

    private async void Device_OnCaptureStopped(object sender, CaptureStoppedEventStatus status)
    {
        if (status == CaptureStoppedEventStatus.CompletedWithoutError) return;

        await Globals.Container.GetInstance<IErrorLogging>().WriteToLogAsync(
            "Couldn't stop capture. An unhandled exception occurred. Such a shame that the library doesn't give us information",
            LogLevel.ERROR);
        ShowNotification(NotificationType.Error,
            "Failed to stop capturing, this is really unusual. You should kill CyberSniff from Task Manager and re-open it.");
    }

    private void Device_OnPacketArrival(object sender, CaptureEventArgs e)
    {
        _ = Task.Run(async () =>
        {
            if (isPoisoning && !arpDevices.IsNullRouted)
                await CheckAndForwardPacketAsync(e.Packet.GetPacket(), (NpcapDevice) GetCurrentCaptureDevice(),
                    arpDevices.TargetPhysicalAddress, arpDevices.SourcePhysicalAddress);
        });
        var now = DateTime.Now;
        var interval = now - lastStatisticsOutput;
        if (interval > lastStatisticsInterval)
        {
            captureStatistics = e.Device.Statistics;
            statisticsUiNeedsUpdate = true;
            lastStatisticsOutput = now;
        }

        lock (queueLock)
        {
            packetQueue.Add(e.Packet);
        }
    }

    private async void DialogHost_DialogClosing(object sender, DialogClosingEventArgs eventArgs)
    {
        if (string.IsNullOrWhiteSpace(TextHost.Text) || string.IsNullOrWhiteSpace(TextLabel.Text) ||
            !await TextHost.Text.ValidateIpAsync()) return;
        Globals.Settings.Labels ??= new List<Label>();
        Globals.Settings.Labels.Add(new Label {IpAddress = TextHost.Text, Name = TextLabel.Text});
        var selectedObject = (CaptureGrid) MainDataGrid.SelectedItem;
        selectedObject.Label = TextLabel.Text;
        TextHost.Text = string.Empty;
        TextLabel.Text = string.Empty;
        dataSource[MainDataGrid.SelectedIndex] = selectedObject;
        Dispatcher.Invoke(() => { dataSource.ResetBindings(); });
    }

    private async void ExportMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is CaptureGrid dgObj)
            await Task.Run(async () =>
            {
                SaveFileDialog dialog = new()
                {
                    Title = "Export capture results...",
                    Filter = "Text document (*.txt) | *.txt",
                    CheckPathExists = true,
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                };
                if (dialog.ShowDialog().Value)
                    await Dispatcher.InvokeAsync(() =>
                    {
                        Globals.Container.GetInstance<IExportDrawer>()
                            .DrawTableForExport(dataSource, dialog.FileName);

                        ShowNotification(NotificationType.Info, $"Successfully exported {dataSource.Count} items");
                    });
            });
    }

    private async void ExportThemeEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            if (currentView is not Settings settings) return;

            settings.ExportThemeButton.IsEnabled = false;
            await Task.Run(async () =>
            {
                SaveFileDialog sfd = new()
                {
                    Filter = "CyberSniff theme file (*.cst) | *.cst;",
                    Title = "Export theme...",
                    CheckPathExists = true,
                    ValidateNames = true,
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                };
                if (sfd.ShowDialog() == true)
                {
                    await Globals.Container.GetInstance<IThemeUtils>().ExportTheme(sfd.FileName);
                    Dispatcher.Invoke(() =>
                    {
                        Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                        {
                            Button = MsgBox.MsgBoxBtn.Ok, Icon = MsgBox.MsgBoxIcon.Success,
                            Message = "Your theme has been exported"
                        });
                    });
                    await Dispatcher.InvokeAsync(() => { settings.ExportThemeButton.IsEnabled = true; });
                    return;
                }

                await Dispatcher.InvokeAsync(() => { settings.ExportThemeButton.IsEnabled = true; });
            });
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private ICaptureDevice GetCurrentCaptureDevice()
    {
        ICaptureDevice captureDevice = null;
        Dispatcher.Invoke(() =>
        {
            captureDevice = CaptureDeviceList.Instance.First(x =>
                x.Name == Adapter.Instance.First(x => x.DisplayName == NetworkAdapterComboBox.Text).Name);
        });
        return captureDevice;
    }

    private void Grid_BeginningEdit(object sender, DataGridBeginningEditEventArgs e)
    {
        e.Cancel = true;
    }

    private async void HandleCaptionsEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            if (e.OriginalSource is not Button button) return;

            switch (button.Name)
            {
                case "CloseButton":
                    CloseButton.IsEnabled = false;
                    Close();
                    break;

                case "MinButton":
                    WindowState = WindowState.Minimized;
                    break;

                case "MaxButton":
                    if (WindowState == WindowState.Maximized)
                    {
                        WindowState = WindowState.Normal;
                        MaxIcon.Kind = PackIconKind.WindowMaximize;
                    }
                    else
                    {
                        WindowState = WindowState.Maximized;
                        MaxIcon.Kind = PackIconKind.WindowRestore;
                    }

                    break;
            }
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void HideSideViewEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            CloseSideView.IsEnabled = false;
            if (settingsView)
            {
                await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
                if (Globals.Settings.Background != "None")
                {
                    if (File.Exists(Globals.Settings.Background.Trim()))
                    {
                        if (Globals.Settings.Background.EndsWith(".gif"))
                        {
                            BackgroundCache = null;
                            GC.Collect();
                            BackgroundCache = new BitmapImage();
                            BackgroundCache.BeginInit();
                            BackgroundCache.UriSource = new Uri(Globals.Settings.Background);
                            BackgroundCache.EndInit();
                            BackgroundImage.Source = BackgroundCache;
                            currentWallpaper = Globals.Settings.Background;
                            ImageBehavior.SetAnimatedSource(BackgroundImage, BackgroundCache);
                        }
                        else
                        {
                            BackgroundCache = null;
                            GC.Collect();
                            BackgroundCache = new BitmapImage();
                            BackgroundCache.BeginInit();
                            BackgroundCache.UriSource = new Uri(Globals.Settings.Background);
                            BackgroundCache.EndInit();
                            BackgroundImage.Source = BackgroundCache;
                            currentWallpaper = Globals.Settings.Background;
                        }
                    }
                    else
                    {
                        BackgroundImage.Source = null;
                        MessageBox.Show(Globals.Settings.Background);
                        ShowNotification(NotificationType.Error, Properties.Resources.BACKGROUND_LOAD_EXCEPTION);
                    }
                }
                else
                {
                    BackgroundCache = new BitmapImage();
                    BackgroundImage.Source = null;
                    currentWallpaper = Globals.Settings.Background;
                }

                Globals.Container.GetInstance<IThemeUtils>().SwitchTheme(new Theme
                {
                    DarkMode = true, PrimaryColor = Globals.Settings.ColorType,
                    SecondaryColor = Globals.Settings.ColorType,
                    CustomColorBrush = (Color) ColorConverter.ConvertFromString(Globals.Settings.HexColor)
                });
                Topmost = Globals.Settings.TopMost;
                AnalyseMenuItem.IsEnabled = Globals.Settings.PacketAnalyser;
                AddToLabelsMenuItem.IsEnabled = Globals.Settings.EnableLabels;
                RenderOptions.ProcessRenderMode =
                    Globals.Settings.HardwareAccel ? RenderMode.Default : RenderMode.SoftwareOnly;
            }

            MaxBottom.IsEnabled = true;
            var hideDim = FindResource("HideDim") as BeginStoryboard;
            hideDim?.Storyboard.Begin();
            await Task.Delay(400);
            CloseSideView.IsEnabled = true;
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private void IconBox_MouseDown(object sender, MouseButtonEventArgs e)
    {
        Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
        {
            Icon = MsgBox.MsgBoxIcon.Information, Button = MsgBox.MsgBoxBtn.Ok,
            Message = Properties.Resources.UI_ABOUT_BOX
        });
    }

    private async void ImportThemeEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            if (currentView is not Settings settings) return;

            settings.ImportThemeButton.IsEnabled = false;
            await Task.Run(async () =>
            {
                OpenFileDialog openFileDialog = new()
                {
                    Filter = "Theme files (*.cst) | *.cst;",
                    Title = "Select theme file...",
                    CheckFileExists = true,
                    CheckPathExists = true,
                    ReadOnlyChecked = true,
                    ValidateNames = true,
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    Multiselect = false
                };
                if (openFileDialog.ShowDialog() == true)
                {
                    await Globals.Container.GetInstance<IThemeUtils>().ImportTheme(openFileDialog.FileName);
                    Border.BorderBrush =
                        new SolidColorBrush(
                            (Color) ColorConverter.ConvertFromString(Globals.Settings.HexColor));
                    if (Globals.Settings.Background != "None")
                    {
                        if (Globals.Settings.Background.EndsWith(".gif"))
                        {
                            BackgroundCache = new BitmapImage();
                            BackgroundCache.BeginInit();
                            BackgroundCache.UriSource = new Uri(Globals.Settings.Background);
                            BackgroundCache.EndInit();
                            BackgroundImage.Source = BackgroundCache;
                            ImageBehavior.SetAnimatedSource(BackgroundImage, BackgroundCache);
                        }
                        else
                        {
                            BackgroundCache = new BitmapImage();
                            BackgroundCache.BeginInit();
                            BackgroundCache.UriSource = new Uri(Globals.Settings.Background);
                            BackgroundCache.EndInit();
                            BackgroundImage.Source = BackgroundCache;
                        }
                    }

                    Dispatcher.Invoke(() =>
                    {
                        Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                        {
                            Button = MsgBox.MsgBoxBtn.Ok, Message = "Imported theme successfully",
                            Icon = MsgBox.MsgBoxIcon.Success
                        });
                    });
                }
                else
                {
                    await Dispatcher.InvokeAsync(() => { settings.ImportThemeButton.IsEnabled = true; });
                }
            });
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void InitAdapters()
    {
        try
        {
            await Dispatcher.InvokeAsync(() =>
            {
                NetworkAdapterComboBox.ItemsSource = Adapter.Instance.Select(x => x.DisplayName);
                if (string.IsNullOrWhiteSpace(Globals.Settings.InterfaceName)) return;
                NetworkAdapterComboBox.SelectedItem =
                    Adapter.Instance.First(x => x.Name == Globals.Settings.InterfaceName).DisplayName;
            });
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
            ShowNotification(NotificationType.Error, Properties.Resources.ADAPTER_EXCEPTION);
        }
    }

    private void Initialize()
    {
        Topmost = false;
        BackgroundCache = new BitmapImage();
        StateChanged += MainWindow_StateChanged;
        MaxHeight = SystemParameters.MaximizedPrimaryScreenHeight;
        MaxWidth = SystemParameters.MaximizedPrimaryScreenWidth;
        MainDataGrid.IsSynchronizedWithCurrentItem = true;
        MaxBottom.IsEnabled = false;

        if (Globals.Settings.DiscordStatus)
        {
            Globals.Container.GetInstance<IDiscordPresenceService>().UpdateDetails("Idle");
            Globals.Container.GetInstance<IDiscordPresenceService>().Initialize();
        }

        if (!Globals.Settings.HardwareAccel)
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
        if (!Globals.Settings.PacketAnalyser)
            AnalyseMenuItem.IsEnabled = false;
        if (!Globals.Settings.EnableLabels)
            AddToLabelsMenuItem.IsEnabled = false;
        if (Globals.Settings.TopMost) Topmost = true;
        if (Globals.Settings.ColorType != ColorType.Default)
            try
            {
                Globals.Container.GetInstance<IThemeUtils>().SwitchTheme(new Theme
                {
                    DarkMode = true, PrimaryColor = Globals.Settings.ColorType,
                    SecondaryColor = Globals.Settings.ColorType,
                    CustomColorBrush =
                        (Color) ColorConverter.ConvertFromString(Globals.Settings.HexColor)
                });
            }
            catch (Exception ex)
            {
                ex.AutoDumpExceptionAsync()
                    .GetAwaiter()
                    .GetResult();
                ShowNotification(NotificationType.Error, Properties.Resources.THEME_APPLY_EXCEPTION);
            }

        if (Globals.Settings.Background != "None")
        {
            Globals.Settings.Background = Globals.Settings.Background.Replace('/', '\\');
            if (File.Exists(Globals.Settings.Background))
                if (Globals.Settings.Background.EndsWith(".gif"))
                {
                    BackgroundCache = new BitmapImage();
                    BackgroundCache.BeginInit();
                    BackgroundCache.UriSource = new Uri(Globals.Settings.Background);
                    BackgroundCache.EndInit();
                    BackgroundImage.Source = BackgroundCache;
                    currentWallpaper = Globals.Settings.Background;
                    ImageBehavior.SetAnimatedSource(BackgroundImage, BackgroundCache);
                }
                else
                {
                    BackgroundCache = new BitmapImage();
                    BackgroundCache.BeginInit();
                    BackgroundCache.UriSource = new Uri(Globals.Settings.Background);
                    BackgroundCache.EndInit();
                    BackgroundImage.Source = BackgroundCache;
                    currentWallpaper = Globals.Settings.Background;
                }
            else
                ShowNotification(NotificationType.Error, Properties.Resources.BACKGROUND_LOAD_EXCEPTION);
        }

        InitAdapters();
        MaxBottom.IsEnabled = true;
        if (!Globals.Settings.AutoShowPanel) TogglePanel();

        Activated += Window_Activated;
        Deactivated += Window_Deactivated;
    }

    private void DimScreen()
    {
        Dimmer.Visibility = Visibility.Visible;
        var dimScreen = FindResource("Dim") as BeginStoryboard;
        dimScreen?.Storyboard.Begin();
    }

    private void LocateMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj) return;

        ChangeSideView(new Locate(dgObj.IpAddress), "Locate host");
        TogglePanel(true);
        MaxBottom.IsEnabled = false;
        Dimmer.Visibility = Visibility.Visible;
        var dimScreen = FindResource("Dim") as BeginStoryboard;
        dimScreen?.Storyboard.Begin();
        var showSettings = FindResource("OpenSettings") as BeginStoryboard;
        showSettings?.Storyboard.Begin();
        settingsView = true;
    }

    private void MainWindow_StateChanged(object sender, EventArgs e)
    {
        MaxIcon.Kind = WindowState == WindowState.Maximized ? PackIconKind.WindowRestore : PackIconKind.WindowMaximize;
    }

    private async void NetworkAdapterComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        Globals.Settings.InterfaceName =
            Adapter.Instance.First(x => x.DisplayName == e.AddedItems.Cast<string>().First()).Name;
        await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
    }

    private async void OpenAdapterEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            if (NetworkAdapterComboBox.SelectedItem == null)
            {
                ShowNotification(NotificationType.Info, "Select an adapter my boy.");
                return;
            }

            AdapterInfoButton.IsEnabled = false;
            TogglePanel(true);
            var item = Adapter.Instance.First(x => x.DisplayName == NetworkAdapterComboBox.Text);
            ChangeSideView(new AdapterInfo(item), "Adapter Info");
            MaxBottom.IsEnabled = false;
            Dimmer.Visibility = Visibility.Visible;
            var dimScreen = FindResource("Dim") as BeginStoryboard;
            dimScreen?.Storyboard.Begin();
            var showSettings = FindResource("OpenSettings") as BeginStoryboard;
            showSettings?.Storyboard.Begin();
            settingsView = true;

            await Task.Delay(400);

            AdapterInfoButton.IsEnabled = true;
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void OpenArpEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            if (NetworkAdapterComboBox.SelectedItem == null)
            {
                ShowNotification(NotificationType.Info, "Select an adapter my boy.");
                return;
            }

            var capDevice = (NpcapDevice) GetCurrentCaptureDevice();
            if (capDevice.GetAddressFamily() == AddressFamily.IPv6)
            {
                ShowNotification(NotificationType.Alert,
                    "You must disable IPv6 to use ARP poisoning");
                return;
            }

            if (capDevice.GetAddressFamily() == AddressFamily.Null)
            {
                ShowNotification(NotificationType.Alert,
                    "This adapter does not have a valid IP address. You may need to connect to the internet using that device");
                return;
            }

            ArpButton.IsEnabled = false;
            var arpWindow = new ArpWindow(capDevice, BackgroundCache, isPoisoning, arpDevices)
            {
                Topmost = Globals.Settings.TopMost,
                Owner = this
            };
            DimScreen();
            arpWindow.Closed += GenericToolWindow_Closed;
            arpWindow.ShowDialog();
            ArpButton.IsEnabled = true;
            await Dispatcher.InvokeAsync(() =>
            {
                isPoisoning = arpWindow.IsPoisoning;
                arpDevices = arpWindow._arpDevices;
            });
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void OpenFiltersEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            FilterButton.IsEnabled = false;
            TogglePanel(true);
            ChangeSideView(new Filters(this), "Filters");
            MaxBottom.IsEnabled = false;
            Dimmer.Visibility = Visibility.Visible;
            var dimScreen = FindResource("Dim") as BeginStoryboard;
            dimScreen?.Storyboard.Begin();
            var showSettings = FindResource("OpenSettings") as BeginStoryboard;
            showSettings?.Storyboard.Begin();
            settingsView = true;
            await Task.Delay(400);
            FilterButton.IsEnabled = true;
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private void GenericToolWindow_Closed(object sender, EventArgs e)
    {
        var unDimScreen = FindResource("HideDim") as BeginStoryboard;
        unDimScreen?.Storyboard.Begin();
    }

    private async void OpenLogEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            if (currentView is Settings settings)
                await Task.Run(async () =>
                {
                    var process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            UseShellExecute = true,
                            FileName = Path.Combine(
                                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CyberSniff",
                                "logfile.log")
                        },
                        EnableRaisingEvents = true
                    };
                    await Dispatcher.InvokeAsync(() => { settings.OpenLogBtn.IsEnabled = false; });
                    process.Start();
                    process.Exited += async (_, _) =>
                    {
                        await Dispatcher.InvokeAsync(() => { settings.OpenLogBtn.IsEnabled = true; });
                    };
                });
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void OpenSettingsEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            SettingsButton.IsEnabled = false;
            TogglePanel(true);
            ChangeSideView(
                new Settings(
                    Tuple.Create(currentWallpaper, NetworkAdapterComboBox.SelectedIndex, Globals.Settings.Filter),
                    this), "Settings");
            MaxBottom.IsEnabled = false;
            Dimmer.Visibility = Visibility.Visible;
            var dimScreen = FindResource("Dim") as BeginStoryboard;
            dimScreen?.Storyboard.Begin();
            var showSettings = FindResource("OpenSettings") as BeginStoryboard;
            showSettings?.Storyboard.Begin();
            settingsView = true;
            await Task.Delay(400);
            SettingsButton.IsEnabled = true;
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void PacketParser(PacketWrapper pw)
    {
        var destPort = 0;
        try
        {
            if (pw.Protocol == ProtocolType.Reserved254) return;

            if (!await Globals.Container.GetInstance<IPacketFilter>().FilterPacketAsync(pw)) return;

            var packet = pw.Packet;
            var isSpoofed = false;

            if (packet == null) return;

            await Dispatcher.InvokeAsync(async () =>
            {
                if (isPoisoning && !arpDevices.IsNullRouted)
                    isSpoofed = await CheckAndForwardPacketAsync(packet, (NpcapDevice) GetCurrentCaptureDevice(),
                        arpDevices.TargetPhysicalAddress, arpDevices.SourcePhysicalAddress);
            });

            var tcpPacket = packet.Extract<TcpPacket>();
            var udpPacket = packet.Extract<UdpPacket>();

            var destinationAddress = IPAddress.Any;
            var flagUri = string.Empty;

            IPPacket ipPacket = null;

            var protocol = pw.Protocol;
            
            switch (protocol)
            {
                case ProtocolType.Tcp when Globals.Settings.Filter is FilterPreset.UDP or FilterPreset.PSNParty
                    or FilterPreset.ApexLegends or FilterPreset.Discord or FilterPreset.GTAVConsole
                    or FilterPreset.RocketLeague or FilterPreset.RecRoom or FilterPreset.uTorrent
                    or FilterPreset.uTorrent or FilterPreset.XboxPartyBETA:
                    return;
                case ProtocolType.Tcp:
                {
                    if (Globals.Settings.Ports.Count != 0)
                    {
                        if (Globals.Settings.PortsInverse)
                        {
                            if (!Globals.Settings.Ports.Contains(tcpPacket.DestinationPort) &&
                                !Globals.Settings.Ports.Contains(tcpPacket.SourcePort))
                                return;
                        }
                        else
                        {
                            if (Globals.Settings.Ports.Contains(tcpPacket.DestinationPort) ||
                                Globals.Settings.Ports.Contains(tcpPacket.SourcePort))
                                return;
                        }
                    }

                    break;
                }
                case ProtocolType.Udp:
                {
                    switch (Globals.Settings.Filter)
                    {
                        case FilterPreset.XboxPartyBETA when udpPacket.PayloadData.Length != 56:
                        case FilterPreset.TCP:
                        case FilterPreset.uTorrent when udpPacket.ValidUdpChecksum && ipPacket.TimeToLive != 128:
                        case FilterPreset.GenericTorrentClient
                            when udpPacket.DestinationPort != 6881 && udpPacket.ValidUdpChecksum:
                            return;
                        case FilterPreset.PSNParty:
                        {
                            var udpPacketLen = udpPacket.PayloadDataSegment.Length;
                            var destPortTmp = udpPacket.DestinationPort;
                            var portLen = udpPacket.DestinationPort.ToString().Length;
                            char[] allowedVals = {'5', '6'};
                            if (udpPacketLen == 64 && portLen == 5)
                            {
                                var valid = allowedVals.Any(x => destPortTmp.ToString().StartsWith(x));

                                if (!valid) return;
                            }
                            else
                            {
                                return;
                            }

                            break;
                        }
                        case FilterPreset.RocketLeague when udpPacket.PayloadData.Length != 80:
                            return;
                        case FilterPreset.ApexLegends:
                        {
                            var destPortTmp = udpPacket.DestinationPort;
                            var portLen = udpPacket.DestinationPort.ToString().Length;
                            if (portLen == 5)
                            {
                                string[] allowedPortPrefixes = {"37", "39"};
                                var valid = allowedPortPrefixes.Any(item => destPortTmp.ToString().StartsWith(item));

                                if (!valid) return;
                            }
                            else
                            {
                                return;
                            }

                            break;
                        }
                        case FilterPreset.RecRoom when udpPacket.DestinationPort != 5056:
                        case FilterPreset.Discord
                            when udpPacket.DestinationPort is <= 50000 or >= 50050:
                        case FilterPreset.RainbowSixSiege when !udpPacket.DestinationPort.ToString().StartsWith("30") &&
                                                               udpPacket.DestinationPort.ToString().Length != 5:
                            return;
                    }

                    if (Globals.Settings.Ports.Count != 0)
                    {
                        if (Globals.Settings.PortsInverse)
                        {
                            if (!Globals.Settings.Ports.Contains(udpPacket.DestinationPort) &&
                                !Globals.Settings.Ports.Contains(udpPacket.SourcePort))
                                return;
                        }
                        else
                        {
                            if (Globals.Settings.Ports.Contains(udpPacket.DestinationPort) ||
                                Globals.Settings.Ports.Contains(udpPacket.SourcePort))
                                return;
                        }
                    }

                    break;
                }
            }

            var status = true;
            switch (protocol)
            {
                case ProtocolType.Tcp:
                    ipPacket = (IPPacket) tcpPacket.ParentPacket;
                    if (!ValidateIPv4(ipPacket.DestinationAddress))
                    {
                        status = false;
                        return;
                    }

                    if (ipPacket.DestinationAddress.ToString().ToLower().StartsWith("f"))
                    {
                        status = false;
                        return;
                    }

                    destPort = tcpPacket.DestinationPort;
                    destinationAddress = ipPacket.DestinationAddress;
                    if (blacklistedPorts.Contains(destPort)) return;
                    if (Globals.Settings.PacketAnalyser)
                        if (!analyserData.TryGetValue(ipPacket.DestinationAddress, out _))
                            analyserData.Add(ipPacket.DestinationAddress, packet);
                    break;

                case ProtocolType.Udp:
                    ipPacket = (IPPacket) udpPacket.ParentPacket;
                    if (!ValidateIPv4(ipPacket.DestinationAddress))
                    {
                        status = false;
                        return;
                    }

                    if (ipPacket.DestinationAddress.ToString().ToLower().StartsWith("f"))
                    {
                        status = false;
                        return;
                    }

                    destPort = udpPacket.DestinationPort;
                    destinationAddress = ipPacket.DestinationAddress;
                    if (blacklistedPorts.Contains(destPort)) return;
                    if (Globals.Settings.PacketAnalyser)
                        if (!analyserData.TryGetValue(ipPacket.DestinationAddress, out var pack))
                            analyserData.Add(ipPacket.DestinationAddress, packet);
                    break;
            }

            if (status)
            {
                var found = false;
                var label = string.Empty;
                foreach (var item in Globals.Settings.Labels.Where(item =>
                             item.IpAddress == destinationAddress.ToString()))
                {
                    found = true;
                    label = item.Name;
                }

                if (found)
                    await Dispatcher.InvokeAsync(() =>
                    {
                        AddToSource(new CaptureGrid
                        {
                            Label = label, Flag = flagUri, IpAddress = destinationAddress, Port = (ushort) destPort,
                            Country = string.Empty, State = string.Empty, City = string.Empty,
                            Isp = string.Empty, DDoSProtected = PackIconKind.Loading,
                            Protocol = protocol.ToString().ToUpper(),
                            Spoofed = isSpoofed ? PackIconKind.SkullCrossbonesOutline : PackIconKind.None
                        });
                    });
                else
                    await Dispatcher.InvokeAsync(() =>
                    {
                        AddToSource(new CaptureGrid
                        {
                            Flag = flagUri, IpAddress = destinationAddress, Port = (ushort) destPort,
                            Country = string.Empty,
                            State = string.Empty, City = string.Empty, Isp = string.Empty,
                            DDoSProtected = PackIconKind.Loading, Protocol = protocol.ToString().ToUpper(),
                            Spoofed = isSpoofed ? PackIconKind.SkullCrossbonesOutline : PackIconKind.None
                        });
                    });
            }
        }
        catch (Exception error)
        {
            await error.AutoDumpExceptionAsync();
        }
    }

    private async void RefreshAdaptersEvent(object sender, ExecutedRoutedEventArgs e)
    {
        IsSniffing = true;
        await Adapter.InitAdapters();
        IsSniffing = false;
    }

    private void RemoveAtMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem == null || MainDataGrid.SelectedItem is not CaptureGrid dgObj) return;

        dataSource.Remove(dataSource[MainDataGrid.SelectedIndex]);
        analyserData.Remove(dgObj.IpAddress);
        ShowNotification(NotificationType.Info, "Removed the selected item.");
    }

    [Obfuscation(Feature = "virtualization", Exclude = false)]
    private async void ResetBackgroundEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            if (currentView is not Settings settings) return;

            var color = (ColorType) settings.ColorComboBox.SelectedItem;
            if (string.IsNullOrWhiteSpace(settings.ColorComboBox.Text)) color = ColorType.Default;
            Globals.Settings.DiscordStatus = settings.ShowDiscordStatusToggle.IsChecked.Value;
            Globals.Settings.AutoShowPanel = settings.AutoShowControlPanelToggle.IsChecked.Value;
            Globals.Settings.PacketAnalyser = settings.PacketAnalyserToggle.IsChecked.Value;
            Globals.Settings.ColorType = color;
            Globals.Settings.ShowFlags = settings.CountryFlagsToggle.IsChecked.Value;
            Globals.Settings.TopMost = settings.TopMostToggle.IsChecked.Value;
            Globals.Settings.Geolocate = settings.GeoToggle.IsChecked.Value;
            Globals.Settings.RememberInterface = settings.RememberAdapterToggle.IsChecked.Value;
            Globals.Settings.HardwareAccel = settings.HardwareAccelToggle.IsChecked.Value;
            Globals.Settings.HexColor = settings.ColorPicker.Color.ToHex();
            Globals.Settings.EnableLabels = settings.LabelToggle.IsChecked.Value;
            var list = new List<Label>();
            foreach (var item in settings.LabelsListBox.Items)
                if (item is string str)
                {
                    var strArrays = str.Split(" IP: ");
                    var obj = new Label {IpAddress = strArrays[1], Name = strArrays[0]};
                    list.Add(obj);
                }

            Globals.Settings.Labels = list;
            Globals.Settings.Background = "None";
            await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
            if (settings.HardwareAccelToggle.IsChecked.Value)
                RenderOptions.ProcessRenderMode = RenderMode.Default;
            if (!settings.HardwareAccelToggle.IsChecked.Value)
                RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
            settings.BackgroundLbl.Text = "Selected: None";
            BackgroundCache = new BitmapImage();
            BackgroundImage.Source = BackgroundCache;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.ToString());
        }
    }

    private async void ResetTitle()
    {
        try
        {
            await Dispatcher.InvokeAsync(() =>
            {
                WindowTitleText.Text =
                    $"CyberSniff-OSS v{Assembly.GetExecutingAssembly().GetCyberSniffVersion()} - Idle";
            });
        }
        catch (Exception)
        {
        }
    }

    [Obfuscation(Feature = "virtualization", Exclude = false)]
    private async void SetBackgroundEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            if (currentView is not Settings settings) return;

            var color = (ColorType) settings.ColorComboBox.SelectedItem;
            if (string.IsNullOrWhiteSpace(settings.ColorComboBox.Text)) color = ColorType.Default;
            Globals.Settings.DiscordStatus = settings.ShowDiscordStatusToggle.IsChecked.Value;
            Globals.Settings.AutoShowPanel = settings.AutoShowControlPanelToggle.IsChecked.Value;
            Globals.Settings.PacketAnalyser = settings.PacketAnalyserToggle.IsChecked.Value;
            Globals.Settings.ColorType = color;
            Globals.Settings.ShowFlags = settings.CountryFlagsToggle.IsChecked.Value;
            Globals.Settings.TopMost = settings.TopMostToggle.IsChecked.Value;
            Globals.Settings.Geolocate = settings.GeoToggle.IsChecked.Value;
            Globals.Settings.RememberInterface = settings.RememberAdapterToggle.IsChecked.Value;
            Globals.Settings.HardwareAccel = settings.HardwareAccelToggle.IsChecked.Value;
            Globals.Settings.HexColor = settings.ColorPicker.Color.ToHex();
            Globals.Settings.EnableLabels = settings.LabelToggle.IsChecked.Value;
            var list = new List<Label>();
            foreach (var item in settings.LabelsListBox.Items)
                if (item is string str)
                {
                    var strArrays = str.Split(" IP: ");
                    var obj = new Label {IpAddress = strArrays[1], Name = strArrays[0]};
                    list.Add(obj);
                }

            Globals.Settings.Labels = list;
            await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
            if (settings.HardwareAccelToggle.IsChecked.Value)
                RenderOptions.ProcessRenderMode = RenderMode.Default;
            if (!settings.HardwareAccelToggle.IsChecked.Value)
                RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
            settings.BackgroundButton.IsEnabled = false;
            settings.ResetBackground.IsEnabled = false;
            await Task.Run(async () =>
            {
                OpenFileDialog openFileDialog = new()
                {
                    Filter =
                        "Supported image files (*.jpg, *.jpeg, *.png, *.bmp, *.jfif, *.gif) | *.jpg; *.jpeg; *.png; *.bmp; *.jfif; *.gif",
                    Title = "Select background image...",
                    CheckFileExists = true,
                    CheckPathExists = true,
                    ReadOnlyChecked = true,
                    ValidateNames = true,
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    Multiselect = false
                };
                if (openFileDialog.ShowDialog() == true)
                    await Dispatcher.Invoke(async () =>
                    {
                        if (!settings.AllowedExtensions.Contains(Path.GetExtension(openFileDialog.FileName)) ||
                            !Globals.Container.GetInstance<IThemeUtils>().IsImage(openFileDialog.FileName))
                        {
                            Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                            {
                                Icon = MsgBox.MsgBoxIcon.Warning, Button = MsgBox.MsgBoxBtn.Ok,
                                Message = Properties.Resources.INVALID_FILE_SELECTED
                            });
                            MessageBox.Show(Properties.Resources.INVALID_FILE_SELECTED, "CyberSniff",
                                MessageBoxButton.OK, MessageBoxImage.Warning);
                            settings.BackgroundButton.IsEnabled = true;
                            settings.ResetBackground.IsEnabled = true;
                            return;
                        }

                        settings.BackgroundLbl.Text = $"Selected: {Path.GetFileName(openFileDialog.FileName)}";
                        settings.BackgroundButton.IsEnabled = true;
                        settings.ResetBackground.IsEnabled = true;
                        var background = openFileDialog.FileName?.Replace('\\', '/');
                        settings.Tuple = Tuple.Create(background, settings.Tuple.Item2,
                            Globals.Settings.Filter);
                        var color = (ColorType) settings.ColorComboBox.SelectedItem;
                        if (string.IsNullOrWhiteSpace(settings.ColorComboBox.Text)) color = ColorType.Default;
                        Globals.Settings.DiscordStatus = settings.ShowDiscordStatusToggle.IsChecked.Value;
                        Globals.Settings.AutoShowPanel = settings.AutoShowControlPanelToggle.IsChecked.Value;
                        Globals.Settings.PacketAnalyser = settings.PacketAnalyserToggle.IsChecked.Value;
                        Globals.Settings.ColorType = color;
                        Globals.Settings.Background = settings.Tuple.Item1;
                        if (settings.Tuple.Item1 != "None")
                        {
                            if (settings.Tuple.Item1.EndsWith(".gif"))
                            {
                                BackgroundCache = null;
                                GC.Collect();
                                BackgroundCache = new BitmapImage();
                                BackgroundCache.BeginInit();
                                BackgroundCache.UriSource = new Uri(settings.Tuple.Item1);
                                BackgroundCache.EndInit();
                                BackgroundImage.Source = BackgroundCache;
                                ImageBehavior.SetAnimatedSource(BackgroundImage, BackgroundCache);
                            }
                            else
                            {
                                BackgroundCache = null;
                                GC.Collect();
                                BackgroundCache = new BitmapImage();
                                BackgroundCache.BeginInit();
                                BackgroundCache.UriSource = new Uri(settings.Tuple.Item1);
                                BackgroundCache.EndInit();
                                BackgroundImage.Source = BackgroundCache;
                            }
                        }

                        Globals.Settings.ShowFlags = settings.CountryFlagsToggle.IsChecked.Value;
                        Globals.Settings.TopMost = settings.TopMostToggle.IsChecked.Value;
                        Globals.Settings.Geolocate = settings.GeoToggle.IsChecked.Value;
                        Globals.Settings.RememberInterface = settings.RememberAdapterToggle.IsChecked.Value;
                        Globals.Settings.HardwareAccel = settings.HardwareAccelToggle.IsChecked.Value;
                        Globals.Settings.HexColor = settings.ColorPicker.Color.ToHex();
                        Globals.Settings.EnableLabels = settings.LabelToggle.IsChecked.Value;
                        var labels = new List<Label>();
                        foreach (var item in settings.LabelsListBox.Items)
                            if (item is string str)
                            {
                                var strArrays = str.Split(" IP: ");
                                var obj = new Label {IpAddress = strArrays[1], Name = strArrays[0]};
                                labels.Add(obj);
                            }

                        Globals.Settings.Labels = labels;
                        await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
                        if (settings.HardwareAccelToggle.IsChecked.Value)
                            RenderOptions.ProcessRenderMode = RenderMode.Default;
                        if (!settings.HardwareAccelToggle.IsChecked.Value)
                            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
                    });
                else
                    await Dispatcher.InvokeAsync(() =>
                    {
                        settings.BackgroundButton.IsEnabled = true;
                        settings.ResetBackground.IsEnabled = true;
                    });
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.ToString());
        }
    }

    [Obfuscation(Feature = "virtualization", Exclude = false)]
    private async void SettingsLoadHandlerEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (currentView is not Settings settings) return;

        if (Globals.Settings.DiscordStatus != settings.ShowDiscordStatusToggle.IsChecked.Value)
        {
            if (settings.ShowDiscordStatusToggle.IsChecked.Value)
                try
                {
                    Globals.Container.GetInstance<IDiscordPresenceService>().Initialize();
                }
                catch (Exception)
                {
                    return;
                }
            else
                try
                {
                    Globals.Container.GetInstance<IDiscordPresenceService>().DeInitialize();
                }
                catch (Exception)
                {
                    return;
                }
        }

        var color = (ColorType) settings.ColorComboBox.SelectedItem;
        if (string.IsNullOrWhiteSpace(settings.ColorComboBox.Text)) color = ColorType.Default;
        Globals.Settings.DiscordStatus = settings.ShowDiscordStatusToggle.IsChecked.Value;
        Globals.Settings.AutoShowPanel = settings.AutoShowControlPanelToggle.IsChecked.Value;
        Globals.Settings.PacketAnalyser = settings.PacketAnalyserToggle.IsChecked.Value;
        Globals.Settings.ColorType = color;
        Globals.Settings.Background = settings.Tuple.Item1;
        if (settings.Tuple.Item1 != "None")
        {
            if (settings.Tuple.Item1.EndsWith(".gif"))
            {
                BackgroundCache = null;
                GC.Collect();
                BackgroundCache = new BitmapImage();
                BackgroundCache.BeginInit();
                BackgroundCache.UriSource = new Uri(settings.Tuple.Item1);
                BackgroundCache.EndInit();
                BackgroundImage.Source = BackgroundCache;
                ImageBehavior.SetAnimatedSource(BackgroundImage, BackgroundCache);
            }
            else
            {
                BackgroundCache = null;
                GC.Collect();
                BackgroundCache = new BitmapImage();
                BackgroundCache.BeginInit();
                BackgroundCache.UriSource = new Uri(settings.Tuple.Item1);
                BackgroundCache.EndInit();
                BackgroundImage.Source = BackgroundCache;
            }
        }

        Globals.Settings.ShowFlags = settings.CountryFlagsToggle.IsChecked.Value;
        Globals.Settings.TopMost = settings.TopMostToggle.IsChecked.Value;
        Globals.Settings.Geolocate = settings.GeoToggle.IsChecked.Value;
        Globals.Settings.RememberInterface = settings.RememberAdapterToggle.IsChecked.Value;
        Globals.Settings.HardwareAccel = settings.HardwareAccelToggle.IsChecked.Value;
        Globals.Settings.HexColor = settings.ColorPicker.Color.ToHex();
        Globals.Settings.EnableLabels = settings.LabelToggle.IsChecked.Value;
        settings.ListGrid.Visibility = Globals.Settings.EnableLabels ? Visibility.Visible : Visibility.Collapsed;
        var list = new List<Label>();
        foreach (var item in settings.LabelsListBox.Items)
            if (item is string str)
            {
                var strArrays = str.Split(" IP: ");
                var obj = new Label {IpAddress = strArrays[1], Name = strArrays[0]};
                list.Add(obj);
            }

        Globals.Settings.Labels = list;
        await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
        if (settings.HardwareAccelToggle.IsChecked.Value) RenderOptions.ProcessRenderMode = RenderMode.Default;
        if (!settings.HardwareAccelToggle.IsChecked.Value)
            RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
    }

    private async void SetTitle(string title)
    {
        await Dispatcher.InvokeAsync(() =>
        {
            WindowTitleText.Text =
                $"CyberSniff-OSS v{Assembly.GetExecutingAssembly().GetCyberSniffVersion()} - {title}";
        });
    }

    private async void ShowNotification(NotificationType type, string message)
    {
        await Dispatcher.InvokeAsync(async () =>
        {
            var openNotificationAnimation = FindResource("OpenNotif") as BeginStoryboard;
            var closeNotificationAnimation = FindResource("CloseNotif") as BeginStoryboard;
            if (isNotificationOpen)
            {
                closeNotificationAnimation?.Storyboard.Begin();
                isNotificationQueued = true;
            }

            isNotificationOpen = true;
            NotificationGrid.Visibility = Visibility.Visible;
            switch (type)
            {
                case NotificationType.Info:
                    NotificationIcon.Kind = PackIconKind.InfoCircleOutline;
                    NotificationTitle.Content = "Notice";
                    NotificationDescription.Text = message;
                    break;

                case NotificationType.Alert:
                    NotificationIcon.Kind = PackIconKind.WarningOutline;
                    NotificationTitle.Content = "Alert";
                    NotificationDescription.Text = message;
                    break;

                case NotificationType.Error:
                    NotificationIcon.Kind = PackIconKind.ErrorOutline;
                    NotificationTitle.Content = "Error";
                    NotificationDescription.Text = message;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }

            openNotificationAnimation?.Storyboard.Begin();
            if (!isNotificationQueued)
            {
                await Task.Delay(3000);
                isNotificationOpen = false;
                closeNotificationAnimation?.Storyboard.Begin();
            }

            isNotificationQueued = false;
        });
    }

    private async void Shutdown()
    {
        try
        {
            if (device != null)
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    IsSniffing = false;
                    SettingsButton.IsEnabled = true;
                    ArpButton.IsEnabled = true;
                    SniffText.Text = "SNIFF";
                    SniffIcon.Kind = PackIconKind.Search;
                    NetworkAdapterComboBox.IsEnabled = true;
                    ipAddresses = null;
                });
                if (isPoisoning)
                {
                    arpThreadStop = true;
                    arpThread.Join();
                }

                ResetTitle();
                Globals.Container.GetInstance<IDiscordPresenceService>().UpdateDetails("Idle");
                Globals.Container.GetInstance<IDiscordPresenceService>().UpdateState(string.Empty);
                device.StopCapture();
                device.Close();
                device.OnPacketArrival -= arrivalEventHandler;
                device.OnCaptureStopped -= captureStoppedEventHandler;
                device = null;
                backgroundThreadStop = true;
                backgroundThread.Join();
                await Dispatcher.InvokeAsync(() => { SniffButton.IsEnabled = true; });
            }
            else
            {
                ShowNotification(NotificationType.Error, "Adapter is null");
            }
        }
        catch (Exception e)
        {
            await e.AutoDumpExceptionAsync();
            Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
            {
                Icon = MsgBox.MsgBoxIcon.Error, Button = MsgBox.MsgBoxBtn.Ok,
                Message = $"{Properties.Resources.GENERIC_EXCEPTION}\n\nWhat happened: {e.Message}"
            });
            Application.Current.Shutdown();
        }
    }

    [Obfuscation(Feature = "virtualization", Exclude = false)]
    private async void StartCapture()
    {
        try
        {
            device = GetCurrentCaptureDevice();
            IsSniffing = true;
            packetCount = 0;
            Dispatcher.Invoke(() => { dataSource.Clear(); });
            SettingsButton.IsEnabled = false;
            ArpButton.IsEnabled = false;
            packetStrings = new Queue<PacketWrapper>();
            lastStatisticsOutput = DateTime.Now;
            backgroundThreadStop = false;
            arpThreadStop = false;
            backgroundThread = new Thread(BackgroundThread)
            {
                Name = "CyberSniff-Capture-Thread",
                Priority = ThreadPriority.AboveNormal,
                IsBackground = true
            };
            backgroundThread.Start();
            blacklistedAddresses = new List<IPAddress>();
            analyserData = new Dictionary<IPAddress, Packet>();
            arrivalEventHandler = Device_OnPacketArrival;
            device.OnPacketArrival += arrivalEventHandler;
            captureStoppedEventHandler = Device_OnCaptureStopped;
            device.OnCaptureStopped += captureStoppedEventHandler;
            device.Open();
            captureStatistics = device.Statistics;
            UpdateCaptureStatistics();
            if (isPoisoning)
            {
                if (arpDevices.SourceLocalAddress == null || arpDevices.SourcePhysicalAddress == null ||
                    arpDevices.TargetLocalAddress == null || arpDevices.TargetPhysicalAddress == null)
                {
                    ShowNotification(NotificationType.Error,
                        "ARP: You need to select a source device and target device!");
                    return;
                }

                arpThread = new Thread(ArpThread)
                {
                    Name = "CyberSniff-ARP-Thread",
                    IsBackground = true,
                    Priority = ThreadPriority.BelowNormal
                };
                arpThread.Start();
            }

            device.StartCapture();
            NetworkAdapterComboBox.IsEnabled = false;

            if (Globals.Settings.DiscordStatus) Globals.Container.GetInstance<IDiscordPresenceService>().Initialize();
            SniffText.Text = "STOP";
            SniffIcon.Kind = PackIconKind.WindowClose;
            SniffButton.IsEnabled = true;
        }
        catch (Exception e)
        {
            await e.AutoDumpExceptionAsync();
            Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
            {
                Icon = MsgBox.MsgBoxIcon.Error, Button = MsgBox.MsgBoxBtn.Ok,
                Message = $"{Properties.Resources.CAPTURE_EXCEPTION}\n\nWhat happened: {e.Message}"
            });
            Environment.Exit(1);
        }
    }

    private void Storyboard_Completed(object sender, EventArgs e)
    {
        if (!settingsView)
        {
            Dimmer.Visibility = Visibility.Hidden;
        }
        else
        {
            Dimmer.Visibility = Visibility.Hidden;
            var hideSettings = FindResource("CloseSettings") as BeginStoryboard;
            hideSettings?.Storyboard.Begin();
            TogglePanel();
            settingsView = false;
        }
    }

    private void Storyboard_Completed_1(object sender, EventArgs e)
    {
        Canvas.Visibility = Visibility.Hidden;
        MaxBottom.IsEnabled = true;
    }

    private void Storyboard_Completed_2(object sender, EventArgs e)
    {
        closeStoryBoardCompleted = true;
        try
        {
            Globals.Container.GetInstance<IDiscordPresenceService>().DeInitialize();
        }
        catch (Exception)
        {
            return;
        }

        Application.Current.Shutdown();
    }

    private void Storyboard_Completed_3(object sender, EventArgs e)
    {
        MaxBottom.IsEnabled = true;
    }

    private void Storyboard_Completed_4(object sender, EventArgs e)
    {
        NotificationGrid.Visibility = Visibility.Hidden;
    }

    private void TcpProbeMenuItemEvent(object sender, ExecutedRoutedEventArgs e)
    {
        if (MainDataGrid.SelectedItem is not CaptureGrid dgObj) return;

        TogglePanel(true);
        ChangeSideView(new Probe(dgObj.IpAddress, dgObj.Port), "TCP Probe");
        MaxBottom.IsEnabled = false;
        Dimmer.Visibility = Visibility.Visible;
        var dimScreen = FindResource("Dim") as BeginStoryboard;
        dimScreen?.Storyboard.Begin();
        var showSettings = FindResource("OpenSettings") as BeginStoryboard;
        showSettings?.Storyboard.Begin();
        settingsView = true;
    }

    [Obfuscation(Feature = "virtualization", Exclude = false)]
    private async void ToggleCaptureEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            SniffButton.IsEnabled = false;
            if (IsSniffing)
            {
                await Task.Run(Shutdown).ConfigureAwait(true);
                return;
            }

            if (NetworkAdapterComboBox.SelectedItem != null)
            {
                dataSource.Clear();
                ipAddresses = new List<IPAddress>();
                TogglePanel();
                StartCapture();
            }
            else
            {
                ShowNotification(NotificationType.Info, "Select an adapter my boy.");
                SniffButton.IsEnabled = true;
            }
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void TogglePanel(bool sideView = false)
    {
        if (sideView)
        {
            await Dispatcher.InvokeAsync(() =>
            {
                if (!isControlPanelOpen) return;

                MaxBottom.IsEnabled = false;
                isControlPanelOpen = false;
                var sb = FindResource("HidePanel") as BeginStoryboard;
                sb?.Storyboard.Begin();
            });
            return;
        }

        await Dispatcher.InvokeAsync(() =>
        {
            if (isControlPanelOpen)
            {
                MaxBottom.IsEnabled = false;
                isControlPanelOpen = false;
                var sb = FindResource("HidePanel") as BeginStoryboard;
                sb?.Storyboard.Begin();
            }
            else
            {
                MaxBottom.IsEnabled = false;
                isControlPanelOpen = true;
                Canvas.Visibility = Visibility.Visible;
                var sb = FindResource("ShowPanel") as BeginStoryboard;
                sb?.Storyboard.Begin();
            }
        });
    }

    private async void TogglePanelEvent(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            TogglePanel();
        }
        catch (Exception ex)
        {
            await ex.AutoDumpExceptionAsync();
        }
    }

    private async void UpdateCaptureStatistics()
    {
        try
        {
            var sniffing = false;
            await Dispatcher.InvokeAsync(() => { sniffing = IsSniffing; });
            if (!sniffing)
            {
                if (!authTask.IsEnabled)
                {
                    await Globals.Container.GetInstance<IErrorLogging>()
                        .WriteToLogAsync("Authentication thread is dead!", LogLevel.FATAL);
                    await Globals.Container.GetInstance<IErrorLogging>()
                        .WriteToLogAsync("Restarting authentication thread...", LogLevel.WARNING);
                    authTask.Start();
                }

                SetTitle("Idle");
                if (!Globals.Settings.DiscordStatus) return;

                Globals.Container.GetInstance<IDiscordPresenceService>().UpdateDetails("Idle");

                return;
            }

            if (Globals.Settings.DiscordStatus)
            {
                Globals.Container.GetInstance<IDiscordPresenceService>().UpdateDetails("Capturing");
                Globals.Container.GetInstance<IDiscordPresenceService>().UpdateState(
                    $"Received {captureStatistics.ReceivedPackets} and dropped {captureStatistics.DroppedPackets} packet(s)");
            }

            SetTitle(
                $"Capturing - Received {captureStatistics.ReceivedPackets} Dropped: {captureStatistics.DroppedPackets}");
        }
        catch (Exception e)
        {
            await e.AutoDumpExceptionAsync();
        }
    }

    private bool ValidateIPv4(IPAddress ipAddr)
    {
        try
        {
            if (ipAddr == null) return false;
            if (string.IsNullOrWhiteSpace(ipAddr.ToString()) || ipAddr.ToString().StartsWith("10.") ||
                ipAddr.ToString().StartsWith("192.168") || ipAddr.ToString().StartsWith("172") ||
                ipAddr.ToString().StartsWith("255.255") || ipAddr.ToString().Contains("ff") ||
                ipAddr.ToString().Contains("255.255") || ipAddr.ToString().Contains("0.0")) return false;
            if (blacklistedAddresses == null && blacklistedAddresses.Count == 0) return true;

            return !blacklistedAddresses.Contains(ipAddr);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private void Window_Activated(object sender, EventArgs e)
    {
        try
        {
            Border.BorderBrush = Globals.Settings.ColorType switch
            {
                ColorType.Custom => new SolidColorBrush(
                    (Color) ColorConverter.ConvertFromString(Globals.Settings.HexColor)),
                ColorType.Accent => new SolidColorBrush(SystemParameters.WindowGlassColor),
                ColorType.Default => new SolidColorBrush(Color.FromRgb(255, 87, 34)),
                _ => new SolidColorBrush(
                    (Color) ColorConverter.ConvertFromString(Globals.Settings.ColorType.ToString()))
            };
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.ToString());
        }
    }

    private async void Window_Closing(object sender, CancelEventArgs e)
    {
        if (closeStoryBoardCompleted) return;

        if (IsSniffing)
        {
            if (Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                {
                    Icon = MsgBox.MsgBoxIcon.Question, Button = MsgBox.MsgBoxBtn.YesNo,
                    Message = Properties.Resources.CAPTURE_ACTIVE_EXIT
                }) == MsgBox.MsgBoxResult.No)
            {
                e.Cancel = true;
                CloseButton.IsEnabled = true;
                return;
            }

            await Task.Run(Shutdown).ConfigureAwait(true);
        }

        var sb = FindResource("CloseAnim") as BeginStoryboard;
        sb?.Storyboard.Begin();
        e.Cancel = true;
    }

    private void Window_Deactivated(object sender, EventArgs e)
    {
        Border.BorderBrush = new SolidColorBrush(Color.FromRgb(64, 64, 64));
    }
}