using System;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using CyberSniff.Classes;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using CyberSniff.Windows;
using MaterialDesignThemes.Wpf;

namespace CyberSniff.Views
{
    public partial class Filters : Page
    {
        private readonly BindingList<FilterPreset> comboBoxSource = new();

        private readonly BindingList<ushort> portBoxSource = new(Globals.Settings.Ports);

        public Filters(MainWindow host)
        {
            InitializeComponent();
            foreach (FilterPreset val in Enum.GetValues(typeof(FilterPreset))) comboBoxSource.Add(val);
            FilterComboBox.ItemsSource = comboBoxSource;
            FilterComboBox.SelectedItem = Globals.Settings.Filter;
            PortListBox.ItemsSource = portBoxSource;
            InvertPortFilterToggle.IsChecked = Globals.Settings.PortsInverse;
            InvertPortFilterToggle.Unchecked += (_, _) => { ApplyFiltersAsync(); };
            InvertPortFilterToggle.Checked += (_, _) => { ApplyFiltersAsync(); };
        }

        private async void ApplyFiltersAsync()
        {
            await Dispatcher.InvokeAsync(() =>
            {
                Globals.Settings.Filter = (FilterPreset) FilterComboBox.SelectedItem;
                Globals.Settings.PortsInverse = InvertPortFilterToggle.IsChecked.Value;
            });
            await Globals.Container.GetInstance<IServerSettings>().UpdateSettingsAsync();
        }

        private void CopyPortItem_Click(object sender, RoutedEventArgs e)
        {
            if (PortListBox.SelectedItem != null)
                PortListBox.SelectedItem.ToString().CopyToClipboard();
        }

        private void DeletePortItem_Click(object sender, RoutedEventArgs e)
        {
            if (PortListBox.SelectedItem != null)
                portBoxSource.Remove(Convert.ToUInt16(PortListBox.SelectedItem));
        }

        private void DialogHost_Closed(object sender, DialogClosingEventArgs eventArgs)
        {
            if (!Equals(eventArgs.Parameter, true))
                return;

            if (!ushort.TryParse(PortText.Text, out var port) || portBoxSource.Contains(port)) return;
            
            PortText.Text = string.Empty;
            portBoxSource.Add(port);
        }

        private async void HandleControlChanges(object sender, RoutedEventArgs e)
        {
            await Task.Run(ApplyFiltersAsync);
        }
    }
}