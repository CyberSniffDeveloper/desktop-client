using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using MaterialDesignThemes.Wpf;
using Newtonsoft.Json;
using SharpPcap;
using SharpPcap.Npcap;
using DataGridTextColumn = System.Windows.Controls.DataGridTextColumn;

namespace CyberSniff.Windows
{
    public partial class ArpWindow : Window
    {
        public static readonly RoutedUICommand AddCommand =
            new("Add", "AddCommand", typeof(ArpWindow));

        public static readonly DependencyProperty IsAddingProperty =
            DependencyProperty.Register("IsAdding", typeof(bool),
                typeof(Window), new UIPropertyMetadata(false));

        public static readonly DependencyProperty IsPoisoningProperty =
            DependencyProperty.Register("IsPoisoning", typeof(bool),
                typeof(Window), new UIPropertyMetadata(false));

        public static readonly DependencyProperty IsScanningProperty =
            DependencyProperty.Register("IsScanning", typeof(bool),
                typeof(Window), new UIPropertyMetadata(false));

        public static readonly RoutedUICommand ScanCommand =
            new("Scan", "ScanCommand", typeof(ArpWindow));

        public static readonly RoutedUICommand TogglePoisonCommand =
            new("Poison", "TogglePoisonCommand", typeof(ArpWindow));

        public ArpDevice _arpDevices;

        private readonly BindingList<ArpOutput> _dataSource = new();

        private readonly ICaptureDevice _device;

        private readonly List<IPAddress> _localAddresses = new();

        private readonly NpcapDevice _npcapDevice;

        private bool closeStoryBoardCompleted;

        public ArpWindow(ICaptureDevice device, ImageSource bitmap, bool isPoisoning = false,
            ArpDevice arpDevices = new())
        {
            try
            {
                InitializeComponent();

                _device = device;
                _npcapDevice = (NpcapDevice) device;
                _arpDevices = arpDevices;
                _dataSource.RaiseListChangedEvents = true;
                _dataSource.ListChanged += DataSource_Updated;
                IsPoisoning = isPoisoning;
                if (IsPoisoning)
                {
                    PoisonButtonText.Text = "STOP POISONING";
                    PoisonButtonIcon.Kind = PackIconKind.Stop;
                }

                _npcapDevice = (NpcapDevice) device;
                InitializeDataGrid(FromDeviceList);
                InitializeDataGrid(ToDeviceList);
                AssignSources(FromDeviceList);
                AssignSources(ToDeviceList);
                if (bitmap != null) BackgroundImage.Source = bitmap;
                IsScanning = true;
                TitleBox.Text = $"CyberSniff-OSS v{Assembly.GetExecutingAssembly().GetCyberSniffVersion()} - ARP Poisoning";
                CommandBindings.Add(new CommandBinding(AddCommand, AddCommandEvent));
                CommandBindings.Add(new CommandBinding(ScanCommand, ScanCommandEvent));
                CommandBindings.Add(new CommandBinding(TogglePoisonCommand, TogglePoisonCommandEvent));
                if (_npcapDevice == null || _device == null) return;
            }
            catch (Exception e)
            {
                _ = e.AutoDumpExceptionAsync();
            }
        }

        public bool IsAdding
        {
            get => (bool) GetValue(IsAddingProperty);
            set => SetValue(IsAddingProperty, value);
        }

        public bool IsPoisoning
        {
            get => (bool) GetValue(IsPoisoningProperty);
            set => SetValue(IsPoisoningProperty, value);
        }

        public bool IsScanning
        {
            get => (bool) GetValue(IsScanningProperty);
            set => SetValue(IsScanningProperty, value);
        }

        private static string ConvertMacToString(PhysicalAddress address)
        {
            return BitConverter.ToString(address.GetAddressBytes()).Replace('-', ':');
        }

        private static void InitializeDataGrid(DataGrid dataGrid)
        {
            DataGridTextColumn col1 = new();
            DataGridTextColumn col2 = new();
            DataGridTextColumn col3 = new();
            dataGrid.Columns.Add(col1);
            dataGrid.Columns.Add(col2);
            dataGrid.Columns.Add(col3);
            col1.Binding = new Binding("LocalAddress");
            col2.Binding = new Binding("MacAddress");
            col3.Binding = new Binding("MacVendor");
            col1.Header = "IP";
            col2.Header = "MAC Address";
            col3.Header = "Manufacturer";
        }

        [Obfuscation(Feature = "virtualization", Exclude = false)]
        private async void AddCommandEvent(object sender, ExecutedRoutedEventArgs e)
        {
            try
            {
                if (!IPAddress.TryParse(DeviceIpAddressTextBox.Text, out var address)) return;
                if (_localAddresses.Contains(address)) return;
                AddBtn.IsEnabled = false;
                IsAdding = true;
                AddDeviceButtonText.Text = "ADDING...";
                DeviceIpAddressTextBox.IsEnabled = false;
                Process addToArpTbl = new()
                {
                    StartInfo = new ProcessStartInfo
                    {
                        Arguments = $"{address} -n 1",
                        FileName = "PING.EXE",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                addToArpTbl.EnableRaisingEvents = true;
                addToArpTbl.Start();
                addToArpTbl.BeginOutputReadLine();
                addToArpTbl.OutputDataReceived += async (_, args) =>
                {
                    try
                    {
                        if (string.IsNullOrWhiteSpace(args.Data)) return;
                        if (args.Data.ToLower().Contains("unreachable"))
                        {
                            MessageBox.Show(
                                "Could not add this device to the ARP routing table, please make sure that you entered a valid local IP address",
                                "CyberSniff", MessageBoxButton.OK, MessageBoxImage.Warning);
                            return;
                        }

                        if (args.Data.ToLower().Contains("failure"))
                            MessageBox.Show(
                                "Failed to send ARP resolution packet, please check your internet connection",
                                "CyberSniff", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                    catch (Exception ex)
                    {
                        await ex.AutoDumpExceptionAsync();
                    }
                };
                addToArpTbl.Exited += (_, _) =>
                {
                    Process getMacProcess = new()
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            Arguments = $"-a {address}",
                            FileName = "ARP.EXE",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        }
                    };
                    getMacProcess.EnableRaisingEvents = true;
                    getMacProcess.Start();
                    getMacProcess.BeginOutputReadLine();
                    getMacProcess.OutputDataReceived += async (_, args) =>
                    {
                        try
                        {
                            if (string.IsNullOrWhiteSpace(args.Data)) return;
                            if (!args.Data.Trim().EndsWith("static") && !args.Data.Trim().EndsWith("dynamic")) return;
                            
                            var regexMac = Regex.Match(args.Data, "(.{2}-.{2}-.{2}-.{2}-.{2}-.{2})").Groups[0].Value
                                .ToUpper();
                            if (string.IsNullOrEmpty(regexMac))
                            {
                                MessageBox.Show(
                                    "Could not get MAC address for the specified local address, this is very unusual. Please make sure you are connected to the internet",
                                    "CyberSniff", MessageBoxButton.OK, MessageBoxImage.Warning);
                                return;
                            }

                            await Dispatcher.InvokeAsync(() =>
                            {
                                _localAddresses.Add(address);
                                var output = new ArpOutput
                                {
                                    LocalAddress = address, MacAddress = PhysicalAddress.Parse(regexMac),
                                    MacVendor = string.Empty
                                };
                                _dataSource.Add(output);
                                FromDeviceList.ScrollIntoView(output);
                                ToDeviceList.ScrollIntoView(output);
                            });
                        }
                        catch (Exception ex)
                        {
                            await ex.AutoDumpExceptionAsync();
                        }
                    };
                    getMacProcess.Exited += async (_, _) =>
                    {
                        try
                        {
                            await Dispatcher.InvokeAsync(() =>
                            {
                                IsAdding = false;
                                AddBtn.IsEnabled = true;
                                AddDeviceButtonText.Text = "ADD DEVICE";
                                DeviceIpAddressTextBox.IsEnabled = true;
                            });
                        }
                        catch (Exception ex)
                        {
                            await ex.AutoDumpExceptionAsync();
                        }
                    };
                };
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
                MessageBox.Show($"{Properties.Resources.GENERIC_EXCEPTION}\n\nWhat happened: {ex.Message}",
                    "CyberSniff", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private async void Arp_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                await Task.Run(ScanLocalDevices);
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
            }
        }

        private void AssignSources(ItemsControl dataGrid)
        {
            dataGrid.ItemsSource = _dataSource;
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
            CloseButton.IsEnabled = false;
        }

        private void DataGridView_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            e.Handled = true;
        }

        [Obfuscation(Feature = "virtualization", Exclude = false)]
        private async void DataSource_Updated(object sender, ListChangedEventArgs e)
        {
            if (e.ListChangedType == ListChangedType.ItemAdded)
                await Task.Run(async () =>
                {
                    if (_dataSource[e.NewIndex] is var gridObject)
                        try
                        {
                            if (string.IsNullOrWhiteSpace(gridObject.MacVendor))
                            {
                                gridObject.MacVendor = "N/A";
                                _dataSource[e.NewIndex] = gridObject;
                                await Dispatcher.InvokeAsync(() => { _dataSource.ResetBindings(); });
                            }
                        }
                        catch (Exception ex)
                        {
                            await ex.AutoDumpExceptionAsync();
                        }
                });
        }

        private void Grid_BeginningEdit(object sender, DataGridBeginningEditEventArgs e)
        {
            e.Cancel = true;
        }

        private void HandleMenuItems(object sender, RoutedEventArgs e)
        {
            if (sender is not MenuItem menuItem) return;
            
            switch (menuItem.Name)
            {
                case "CopyMac1":
                    if (FromDeviceList.SelectedItem == null) return;
                    var obj = (ArpOutput) FromDeviceList.SelectedItem;
                    if (obj.MacAddress != null) ConvertMacToString(obj.MacAddress).CopyToClipboard();
                    break;

                case "CopyMac2":
                    if (ToDeviceList.SelectedItem == null) return;
                    var obj1 = (ArpOutput) ToDeviceList.SelectedItem;
                    if (obj1.MacAddress != null) ConvertMacToString(obj1.MacAddress).CopyToClipboard();
                    break;

                case "CopyAddress1":
                    if (FromDeviceList.SelectedItem == null) return;
                    var obj2 = (ArpOutput) FromDeviceList.SelectedItem;
                    obj2.LocalAddress?.ToString().CopyToClipboard();
                    break;

                case "CopyAddress2":
                    if (ToDeviceList.SelectedItem == null) return;
                    var obj3 = (ArpOutput) ToDeviceList.SelectedItem;
                    obj3.LocalAddress?.ToString().CopyToClipboard();
                    break;
            }
        }

        private void MinButton_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private async void ScanCommandEvent(object sender, ExecutedRoutedEventArgs e)
        {
            try
            {
                _dataSource.Clear();
                await Task.Run(ScanLocalDevices);
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
            }
        }

        [Obfuscation(Feature = "virtualization", Exclude = false)]
        private async void ScanLocalDevices()
        {
            try
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    IsScanning = true;
                    ScanButtonText.Text = "SCANNING...";
                });
                Process process = new()
                {
                    StartInfo = new ProcessStartInfo
                    {
                        Arguments = $"-a -N {_npcapDevice.Addresses[0].Addr.ipAddress}",
                        FileName = "arp.exe",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.EnableRaisingEvents = true;
                process.Start();
                process.BeginOutputReadLine();
                process.OutputDataReceived += async (sender, e) =>
                {
                    try
                    {
                        if (string.IsNullOrWhiteSpace(e.Data)) return;
                        if (!e.Data.Trim().EndsWith("static") && !e.Data.Trim().EndsWith("dynamic")) return;
                        
                        var regexMac = Regex.Match(e.Data, "(.{2}-.{2}-.{2}-.{2}-.{2}-.{2})").Groups[0].Value
                            .ToUpper();
                        var regexIpv4 = Regex.Match(e.Data, @"(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})").Groups[0].Value;
                        if (!IPAddress.TryParse(regexIpv4, out var address)) return;
                        if (string.IsNullOrEmpty(regexMac)) return;
                        if (regexIpv4.Split('.')[0] !=
                            _npcapDevice.Interface.GatewayAddresses[0].ToString().Split('.')[0] ||
                            regexIpv4.Contains("255")) return;
                        await Dispatcher.InvokeAsync(() =>
                        {
                            _localAddresses.Add(address);
                            var model = new ArpOutput
                            {
                                LocalAddress = address, MacAddress = PhysicalAddress.Parse(regexMac),
                                MacVendor = string.Empty
                            };
                            _dataSource.Add(model);
                        });
                    }
                    catch (Exception ex)
                    {
                        await ex.AutoDumpExceptionAsync();
                        Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                        {
                            Icon = MsgBox.MsgBoxIcon.Error, Button = MsgBox.MsgBoxBtn.Ok,
                            Message = $"{Properties.Resources.GENERIC_EXCEPTION}\n\nWhat happened: {ex.Message}"
                        });
                    }
                };
                process.Exited += async (_, _) =>
                {
                    await Dispatcher.InvokeAsync(() =>
                    {
                        ScanButtonText.Text = " SCAN";
                        IsScanning = false;
                    });
                };
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
                MessageBox.Show("Failed to scan for devices", "CyberSniff", MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }

        private void Storyboard_Completed(object sender, EventArgs e)
        {
            closeStoryBoardCompleted = true;
            Close();
        }

        private async void TogglePoisonCommandEvent(object sender, ExecutedRoutedEventArgs e)
        {
            try
            {
                if (IsPoisoning)
                {
                    IsPoisoning = false;
                    PoisonButtonText.Text = "START POISONING";
                    PoisonButtonIcon.Kind = PackIconKind.Play;
                    return;
                }

                if (FromDeviceList.SelectedItem == null || ToDeviceList.SelectedItem == null)
                {
                    Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                    {
                        Button = MsgBox.MsgBoxBtn.Ok, Icon = MsgBox.MsgBoxIcon.Warning,
                        Message = "You must select a source device and a target device to ARP poison"
                    });
                    return;
                }

                if (Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                {
                    Icon = MsgBox.MsgBoxIcon.Question, Button = MsgBox.MsgBoxBtn.YesNo,
                    Message =
                        "The ARP packet forwarder is currently broken and pending a fix. Meaning if you ARP spoof on a device, the target will disconnect from the internet during ARP spoofing. Do you want to continue?"
                }) == MsgBox.MsgBoxResult.No) return;
                IsPoisoning = true;
                PoisonButtonText.Text = "STOP POISONING";
                PoisonButtonIcon.Kind = PackIconKind.Stop;

                var fromArpRow = (ArpOutput) FromDeviceList.SelectedItem;
                var toArpRow = (ArpOutput) ToDeviceList.SelectedItem;
                if (toArpRow.MacAddress == null || fromArpRow.MacAddress == null) return;
                IsPoisoning = true;
                _arpDevices = new ArpDevice
                {
                    SourceLocalAddress = fromArpRow.LocalAddress, SourcePhysicalAddress = fromArpRow.MacAddress,
                    TargetLocalAddress = toArpRow.LocalAddress, TargetPhysicalAddress = toArpRow.MacAddress,
                    IsNullRouted = NullRouteToggle.IsChecked.Value
                };
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
            }
            finally
            {
                _device.Close();
            }
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            if (closeStoryBoardCompleted) return;
            
            var sb = FindResource("CloseAnim") as BeginStoryboard;
            sb?.Storyboard.Begin();
            e.Cancel = true;
        }

        public struct ArpOutput : INotifyPropertyChanged
        {
            private IPAddress localAddress;

            private PhysicalAddress macAddress;

            private string macVendor;

            public event PropertyChangedEventHandler PropertyChanged;

            public IPAddress LocalAddress
            {
                get => localAddress;

                set
                {
                    localAddress = value;
                    OnPropertyChanged(nameof(LocalAddress));
                }
            }

            public PhysicalAddress MacAddress
            {
                get => macAddress;

                set
                {
                    macAddress = value;
                    OnPropertyChanged(nameof(MacAddress));
                }
            }

            public string MacVendor
            {
                get => macVendor;

                set
                {
                    macVendor = value;
                    OnPropertyChanged(nameof(MacVendor));
                }
            }

            private void OnPropertyChanged(string propertyName)
            {
                var saved = PropertyChanged;
                if (saved == null) return;
                
                var e = new PropertyChangedEventArgs(propertyName);
                saved(this, e);
            }
        }
    }
}