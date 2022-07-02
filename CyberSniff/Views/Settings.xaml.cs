using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using System.Windows.Media;
using CyberSniff.Classes;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using CyberSniff.Windows;
using MaterialDesignThemes.Wpf;
using Label = CyberSniff.Models.Label;
using Theme = CyberSniff.Models.Theme;

namespace CyberSniff.Views
{
    public partial class Settings : Page
    {
        public Tuple<string, int, FilterPreset> Tuple;

        public readonly List<string> AllowedExtensions = new()
        {
            ".jpg",
            ".jpeg",
            ".png",
            ".bmp",
            ".jfif",
            ".gif"
        };

        private readonly MainWindow host;

        public Settings(Tuple<string, int, FilterPreset> tuple, MainWindow host)
        {
            try
            {
                InitializeComponent();
            }
            catch (Exception e)
            {
                _ = e.AutoDumpExceptionAsync();
                MessageBox.Show($"{Properties.Resources.GENERIC_EXCEPTION}\n\nWhat happened: {e.Message}", "CyberSniff",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                Environment.Exit(0);
                return;
            }

            Tuple = tuple ?? throw new ArgumentException(nameof(Tuple));
            this.host = host ?? throw new ArgumentException(nameof(Tuple));
            foreach (var value in Enum.GetValues(typeof(ColorType))) ColorComboBox.Items.Add(value);
            ColorComboBox.SelectedItem = Globals.Settings.ColorType;
            ColorPicker.Color = (Color) ColorConverter.ConvertFromString(Globals.Settings.HexColor ?? string.Empty);
            HexColorField.Text = Globals.Settings.HexColor;
            ShowDiscordStatusToggle.IsChecked = Globals.Settings.DiscordStatus;
            GeoToggle.IsChecked = Globals.Settings.Geolocate;
            PacketAnalyserToggle.IsChecked = Globals.Settings.PacketAnalyser;
            CountryFlagsToggle.IsChecked = Globals.Settings.ShowFlags;
            TopMostToggle.IsChecked = Globals.Settings.TopMost;
            RememberAdapterToggle.IsChecked = Globals.Settings.RememberInterface;
            HardwareAccelToggle.IsChecked = Globals.Settings.HardwareAccel;
            AutoShowControlPanelToggle.IsChecked = Globals.Settings.AutoShowPanel;
            BackgroundLbl.Text = "Selected: " + Path.GetFileName(Globals.Settings.Background);
            LabelToggle.IsChecked = Globals.Settings.EnableLabels;
            if (Globals.Settings.EnableLabels)
            {
                ListGrid.Visibility = Visibility.Visible;
                LabelsTitle.Visibility = Visibility.Visible;
            }
            else
            {
                ListGrid.Visibility = Visibility.Collapsed;
                LabelsTitle.Visibility = Visibility.Collapsed;
            }

            if (Globals.Settings.ColorType == ColorType.Custom)
            {
                CustomColorPickerGrid.Visibility = Visibility.Visible;
                try
                {
                    ColorPicker.Color = (Color) ColorConverter.ConvertFromString(Globals.Settings.HexColor);
                }
                catch (Exception e)
                {
                    _ = e.AutoDumpExceptionAsync();
                    Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                    {
                        Icon = MsgBox.MsgBoxIcon.Error, Button = MsgBox.MsgBoxBtn.Ok,
                        Message = $"{Properties.Resources.GENERIC_EXCEPTION}\n\nWhat happened: {e.Message}"
                    });
                    Environment.Exit(0);
                    return;
                }
            }

            foreach (var item in Globals.Settings.Labels)
            {
                var itemStr = $"{item.Name} IP: {item.IpAddress}";
                LabelsListBox.Items.Add(itemStr);
            }

            ColorComboBox.SelectionChanged += HandleControlChanges;
            HexColorField.TextChanged += HandleControlChanges;
        }

        public async void ApplySettings()
        {
            await Dispatcher.InvokeAsync(() =>
            {
                if (ColorComboBox.SelectedItem is ColorType colorType)
                {
                    if (string.IsNullOrWhiteSpace(ColorComboBox.Text)) colorType = ColorType.Default;
                    Globals.Settings.DiscordStatus = ShowDiscordStatusToggle.IsChecked.Value;
                    Globals.Settings.AutoShowPanel = AutoShowControlPanelToggle.IsChecked.Value;
                    Globals.Settings.PacketAnalyser = PacketAnalyserToggle.IsChecked.Value;
                    Globals.Settings.ColorType = colorType;
                    Globals.Settings.Background = Tuple.Item1;
                    Globals.Settings.ShowFlags = CountryFlagsToggle.IsChecked.Value;
                    Globals.Settings.TopMost = TopMostToggle.IsChecked.Value;
                    Globals.Settings.Geolocate = GeoToggle.IsChecked.Value;
                    Globals.Settings.RememberInterface = RememberAdapterToggle.IsChecked.Value;
                    Globals.Settings.HardwareAccel = HardwareAccelToggle.IsChecked.Value;
                    Globals.Settings.HexColor = ColorPicker.Color.ToHex();
                    Globals.Settings.Filter = Tuple.Item3;
                    Globals.Settings.EnableLabels = LabelToggle.IsChecked.Value;
                    var list = new List<Label>();
                    foreach (var item in LabelsListBox.Items)
                        if (item is string str)
                        {
                            var strArrays = str.Split(" IP: ");
                            var obj = new Label {IpAddress = strArrays[1], Name = strArrays[0]};
                            list.Add(obj);
                        }

                    Globals.Settings.Labels = list;
                    if (HardwareAccelToggle.IsChecked.Value) RenderOptions.ProcessRenderMode = RenderMode.Default;
                    if (!HardwareAccelToggle.IsChecked.Value) RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;
                }
            });
        }

        private void ColorPicker_ColorChanged(object sender, RoutedPropertyChangedEventArgs<Color> e)
        {
            HexColorField.Text = e.NewValue.ToHex();
        }

        private void CopyIpLbl_Click(object sender, RoutedEventArgs e)
        {
            if (LabelsListBox.SelectedItem == null) return;
            var selectedItem = (string) LabelsListBox.SelectedItem;
            selectedItem.Split(" IP: ")[1].CopyToClipboard();
        }

        private void CopyLabel_Click(object sender, RoutedEventArgs e)
        {
            if (LabelsListBox.SelectedItem == null) return;
            var selectedItem = (string) LabelsListBox.SelectedItem;
            selectedItem.Split(" IP: ")[0].CopyToClipboard();
        }

        private void DeleteAllLabels_Click(object sender, RoutedEventArgs e)
        {
            LabelsListBox.Items.Clear();
            ApplySettings();
        }

        private void DeleteSelectedLabel_Click(object sender, RoutedEventArgs e)
        {
            if (LabelsListBox.SelectedItem == null) return;
            var selectedItem = (string) LabelsListBox.SelectedItem;
            LabelsListBox.Items.Remove(selectedItem);
            ApplySettings();
        }

        private async void DialogHost_DialogClosing(object sender, DialogClosingEventArgs eventArgs)
        {
            if (string.IsNullOrWhiteSpace(HostText.Text) || string.IsNullOrWhiteSpace(LabelText.Text) ||
                !await HostText.Text.ValidateIpAsync()) return;
            if (LabelsListBox.Items.Contains(new Label {IpAddress = HostText.Text, Name = LabelText.Text})) return;
            LabelsListBox.Items.Add($"{LabelText.Text} IP: {HostText.Text}");
            HostText.Text = string.Empty;
            LabelText.Text = string.Empty;
            ApplySettings();
        }

        private async void HandleControlChanges(object sender, RoutedEventArgs e)
        {
            try
            {
                switch (sender)
                {
                    case null:
                        return;
                    case ComboBox when ColorComboBox.SelectedItem is ColorType colorType:
                    {
                        if (colorType == ColorType.Custom)
                        {
                            Globals.Container.GetInstance<IThemeUtils>().SwitchTheme(new Theme
                            {
                                DarkMode = true, PrimaryColor = colorType,
                                SecondaryColor = colorType,
                                CustomColorBrush = (Color) ColorConverter.ConvertFromString(HexColorField.Text)
                            });
                            CustomColorPickerGrid.Visibility = Visibility.Visible;
                            return;
                        }

                        await Dispatcher.InvokeAsync(() =>
                        {
                            Globals.Container.GetInstance<IThemeUtils>().SwitchTheme(new Theme
                            {
                                DarkMode = true, PrimaryColor = (ColorType) ColorComboBox.SelectedItem,
                                SecondaryColor = (ColorType) ColorComboBox.SelectedItem
                            });
                            if (colorType != ColorType.Accent)
                                host.Border.BorderBrush =
                                    new SolidColorBrush((Color) ColorConverter.ConvertFromString(ColorComboBox.Text));
                        });
                        break;
                    }
                    case ComboBox:
                        CustomColorPickerGrid.Visibility = Visibility.Collapsed;
                        MessageBox.Show(
                            $"Failed to convert object to ColorType. This is really unusual. Your settings file is most likely now corrupted, you need to delete the folder %appdata%\\CyberSniff if that's the case. Please report this problem to a developer with the following information.\n\nObject conversion (obj->ColorType) failed, value passed: {ColorComboBox.Text}",
                            "CyberSniff", MessageBoxButton.OK, MessageBoxImage.Error);
                        Environment.Exit(2);
                        return;
                    case TextBox textBox:
                    {
                        if (textBox.Text.StartsWith("#"))
                            try
                            {
                                await Dispatcher.InvokeAsync(() =>
                                {
                                    Globals.Container.GetInstance<IThemeUtils>().SwitchTheme(new Theme
                                    {
                                        DarkMode = true, PrimaryColor = (ColorType) ColorComboBox.SelectedItem,
                                        SecondaryColor = (ColorType) ColorComboBox.SelectedItem,
                                        CustomColorBrush = ColorPicker.Color
                                    });
                                    host.Border.BorderBrush = new SolidColorBrush(ColorPicker.Color);
                                });
                            }
                            catch (Exception)
                            {
                                return;
                            }

                        break;
                    }
                    case ToggleButton toggleButton:
                        switch (toggleButton.Name)
                        {
                            case "LabelToggle":
                                if (LabelToggle.IsChecked.Value == false)
                                {
                                    LabelsTitle.Visibility = Visibility.Collapsed;
                                    ListGrid.Visibility = Visibility.Collapsed;
                                }
                                else
                                {
                                    LabelsTitle.Visibility = Visibility.Visible;
                                    ListGrid.Visibility = Visibility.Visible;
                                }

                                break;
                        }

                        break;
                }

                ApplySettings();
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
            }
        }
    }
}