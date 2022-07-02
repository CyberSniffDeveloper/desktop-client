using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using MaterialDesignThemes.Wpf;
using Newtonsoft.Json;
using SharpPcap;
using SharpPcap.Npcap;
using DataGridTextColumn = System.Windows.Controls.DataGridTextColumn;

namespace CyberSniff.Views
{
    public partial class Arp : Page
    {
        public static readonly RoutedUICommand AddCommand =
            new("Add", "AddCommand", typeof(Arp));

        public static readonly DependencyProperty IsAddingProperty =
            DependencyProperty.Register("IsAdding", typeof(bool),
                typeof(Page), new UIPropertyMetadata(false));

        public static readonly DependencyProperty IsPoisoningProperty =
            DependencyProperty.Register("IsPoisoning", typeof(bool),
                typeof(Page), new UIPropertyMetadata(false));

        public static readonly DependencyProperty IsScanningProperty =
            DependencyProperty.Register("IsScanning", typeof(bool),
                typeof(Page), new UIPropertyMetadata(false));

        public static readonly RoutedUICommand ScanCommand =
            new("Scan", "ScanCommand", typeof(Arp));

        public static readonly RoutedUICommand TogglePoisonCommand =
            new("Poison", "TogglePoisonCommand", typeof(Arp));

        public ArpDevice ArpDevices;

        private readonly BindingList<ArpOutput> dataSource = new();

        private readonly ICaptureDevice device;

        private readonly List<IPAddress> localAddresses = new();

        private readonly NpcapDevice npcapDevice;

        public Arp(ICaptureDevice device, bool isPoisoning = false, ArpDevice arpDevices = new())
        {
            try
            {
                InitializeComponent();
                
                this.device = device;
                npcapDevice = (NpcapDevice) device;
                ArpDevices = arpDevices;
                dataSource.RaiseListChangedEvents = true;
                dataSource.ListChanged += DataSource_Updated;
                IsPoisoning = isPoisoning;
                if (IsPoisoning)
                {
                    PoisonButtonText.Text = "STOP POISONING";
                    PoisonButtonIcon.Kind = PackIconKind.Stop;
                }

                npcapDevice = (NpcapDevice) device;
                InitializeDataGrid(FromDeviceList);
                InitializeDataGrid(ToDeviceList);
                AssignSources(FromDeviceList);
                AssignSources(ToDeviceList);
                IsScanning = true;
                CommandBindings.Add(new CommandBinding(AddCommand, AddCommandEvent));
                CommandBindings.Add(new CommandBinding(ScanCommand, ScanCommandEvent));
                CommandBindings.Add(new CommandBinding(TogglePoisonCommand, TogglePoisonCommandEvent));
                if (npcapDevice == null || this.device == null) return;
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
                if (!IPAddress.TryParse(IpAddressTextBox.Text, out var address)) return;
                if (localAddresses.Contains(address)) return;
                AddBtn.IsEnabled = false;
                IsAdding = true;
                AddDeviceButton.Text = "ADDING...";
                IpAddressTextBox.IsEnabled = false;
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
                addToArpTbl.OutputDataReceived += (_, args) =>
                {
                    if (string.IsNullOrWhiteSpace(args.Data)) return;
                    if (args.Data.ToLower().Contains("unreachable"))
                    {
                        Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                        {
                            Icon = MsgBox.MsgBoxIcon.Warning, Button = MsgBox.MsgBoxBtn.Ok,
                            Message =
                                "Could not add this device to the ARP routing table, please make sure that you entered a valid local IP address"
                        });
                        return;
                    }

                    if (args.Data.ToLower().Contains("failure"))
                        Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                        {
                            Icon = MsgBox.MsgBoxIcon.Warning, Button = MsgBox.MsgBoxBtn.Ok,
                            Message = "Failed to send ARP resolution packet, please check your internet connection"
                        });
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
                    getMacProcess.OutputDataReceived += (_, args) =>
                    {
                        if (string.IsNullOrWhiteSpace(args.Data)) return;
                        if (!args.Data.Trim().EndsWith("static") && !args.Data.Trim().EndsWith("dynamic")) return;
                        
                        var regexMac = Regex.Match(args.Data, "(.{2}-.{2}-.{2}-.{2}-.{2}-.{2})").Groups[0].Value
                            .ToUpper();
                        if (string.IsNullOrEmpty(regexMac))
                        {
                            Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                            {
                                Icon = MsgBox.MsgBoxIcon.Warning, Button = MsgBox.MsgBoxBtn.Ok,
                                Message =
                                    "Could not get MAC address for the specified local address, this is very unusual. Please make sure you are connected to the internet"
                            });

                            return;
                        }

                        localAddresses.Add(address);
                        var output = new ArpOutput
                        {
                            LocalAddress = address, MacAddress = PhysicalAddress.Parse(regexMac),
                            MacVendor = string.Empty
                        };
                        dataSource.Add(output);
                        FromDeviceList.ScrollIntoView(output);
                        ToDeviceList.ScrollIntoView(output);
                    };
                    getMacProcess.Exited += (_, _) =>
                    {
                        IsAdding = false;
                        AddBtn.IsEnabled = true;
                        AddDeviceButton.Text = "ADD DEVICE";
                        IpAddressTextBox.IsEnabled = true;
                    };
                };
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
        }

        private async void Arp_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                await Task.Run(ScanLocalDevices);
                ScanBtn.Click += async (_, _) => { await Task.Run(ScanLocalDevices); };
                MessageBox.Show(dataSource.Select(x => x.MacAddress == ArpDevices.TargetPhysicalAddress).First()
                    .ToString());
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
            }
        }

        private void AssignSources(DataGrid dataGrid)
        {
            dataGrid.ItemsSource = dataSource;
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
                    if (dataSource[e.NewIndex] is var gridObject)
                        try
                        {
                            if (string.IsNullOrWhiteSpace(gridObject.MacVendor))
                            {
                                gridObject.MacVendor = "N/A";
                                dataSource[e.NewIndex] = gridObject;
                                await Dispatcher.InvokeAsync(() => { dataSource.ResetBindings(); });
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

        private async void ScanCommandEvent(object sender, ExecutedRoutedEventArgs e)
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

        [Obfuscation(Feature = "virtualization", Exclude = false)]
        private async void ScanLocalDevices()
        {
            try
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    dataSource.Clear();
                    IsScanning = true;
                    ScanButtonText.Text = "SCANNING...";
                });
                Process process = new()
                {
                    StartInfo = new ProcessStartInfo
                    {
                        Arguments = $"-a -N {npcapDevice.Addresses[0].Addr.ipAddress}",
                        FileName = "arp.exe",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };
                process.EnableRaisingEvents = true;
                process.Start();
                process.BeginOutputReadLine();
                process.OutputDataReceived += async (_, e) =>
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
                            npcapDevice.Interface.GatewayAddresses[0].ToString().Split('.')[0] ||
                            regexIpv4.Contains("255")) return;
                        await Dispatcher.InvokeAsync(() =>
                        {
                            localAddresses.Add(address);
                            var model = new ArpOutput
                            {
                                LocalAddress = address, MacAddress = PhysicalAddress.Parse(regexMac),
                                MacVendor = string.Empty
                            };
                            dataSource.Add(model);
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
                        "Since this hasn't been completed, it's not a good idea to run this. It will spoof, but traffic is not correctly forwarded yet, therefore meaning you may get disconnected on the target device. Do you still want to continue?"
                }) == MsgBox.MsgBoxResult.No) return;
                IsPoisoning = true;
                PoisonButtonText.Text = "STOP POISONING";
                PoisonButtonIcon.Kind = PackIconKind.Stop;
                device.Open();

                var fromArpRow = (ArpOutput) FromDeviceList.SelectedItem;
                var toArpRow = (ArpOutput) ToDeviceList.SelectedItem;
                if (toArpRow.MacAddress == null || fromArpRow.MacAddress == null) return;
                IsPoisoning = true;
                ArpDevices = new ArpDevice
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
                device.Close();
            }
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