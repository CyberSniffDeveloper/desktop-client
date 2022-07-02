using System;
using System.Net;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using CyberSniff.Classes;
using CyberSniff.Models;
using MaterialDesignThemes.Wpf;
using Newtonsoft.Json;

namespace CyberSniff.Views
{
    public partial class Locate : Page
    {
        private readonly IPAddress hostAddress;

        public Locate(IPAddress host)
        {
            InitializeComponent();
            hostAddress = host ?? throw new ArgumentNullException(nameof(host));
            MainScrollViewer.Visibility = Visibility.Hidden;
        }

        [Obfuscation(Feature = "virtualization", Exclude = false)]
        private async void Locate_Loaded(object sender, RoutedEventArgs e)
        {
            TitleText.Text = hostAddress.ToString();
            var resp = await Web.IpLocationAsync(hostAddress);
            if (resp is null)
            {
                CountryText.Text = "Country: N/A";
                ContinentText.Text = "Continent: N/A";
                RegionText.Text = "Region: N/A";
                CityText.Text = "City: N/A";
                ZipText.Text = "Zip: N/A";
                LatitudeText.Text = "Latitude: N/A";
                LongitudeText.Text = "Longitude: N/A";
                TimezoneText.Text = "Timezone: N/A";
                ProviderText.Text = "ISP: N/A";
                OrganizationText.Text = "Organization: N/A";
                AsnText.Text = "ASN: N/A";
                HostnameText.Text = "Hostname: N/A";
                PlayAnim();
                return;
            }
            
            CountryText.Text = $"Country: {resp.Country ?? "N/A"}";
            ContinentText.Text = $"Continent: {resp.Continent ?? "N/A"}";
            RegionText.Text = $"Region: {resp.Region ?? "N/A"}";
            CityText.Text = $"City: {resp.City ?? "N/A"}";
            ZipText.Text = $"Zip: {resp.Zip ?? "N/A"}";
            LatitudeText.Text = $"Latitude: {resp.Latitude ?? "N/A"}";
            LongitudeText.Text = $"Longitude: {resp.Longitude ?? "N/A"}";
            TimezoneText.Text = $"Timezone: {resp.Timezone ?? "N/A"}";
            ProviderText.Text = $"ISP: {resp.Isp ?? "N/A"}";
            OrganizationText.Text = $"Organization: {resp.Organization ?? "N/A"}";
            AsnText.Text = $"ASN: {resp.Asn ?? "N/A"}";
            HostnameText.Text = $"Hostname: {resp.Hostname ?? "N/A"}";
            HostingIcon.Kind = resp.IsHosting ? PackIconKind.Check : PackIconKind.WindowClose;
            ProxyIcon.Kind = resp.IsProxy ? PackIconKind.Check : PackIconKind.WindowClose;
            HotspotIcon.Kind = resp.IsHotspot ? PackIconKind.Check : PackIconKind.WindowClose;

            PlayAnim();
        }

        private void PlayAnim()
        {
            _ = new DoubleAnimation
            {
                From = 1.0,
                To = 0.0,
                FillBehavior = FillBehavior.Stop,
                BeginTime = TimeSpan.FromSeconds(2),
                Duration = new Duration(TimeSpan.FromSeconds(0.5))
            };
            Storyboard storyboard = new();
            var duration = TimeSpan.FromMilliseconds(250);

            DoubleAnimation fadeInAnimation = new()
                {From = 0.0, To = 1.0, Duration = new Duration(duration)};

            DoubleAnimation fadeOutAnimation = new()
                {From = 1.0, To = 0.0, Duration = new Duration(duration)};

            Storyboard.SetTargetName(fadeOutAnimation, LoadingGrid.Name);
            Storyboard.SetTargetProperty(fadeOutAnimation, new PropertyPath("Opacity", 0));
            storyboard.Children.Add(fadeOutAnimation);
            storyboard.Begin(LoadingGrid);

            MainScrollViewer.Opacity = 0;
            MainScrollViewer.Visibility = Visibility.Visible;

            Storyboard.SetTargetName(fadeInAnimation, MainScrollViewer.Name);
            Storyboard.SetTargetProperty(fadeInAnimation, new PropertyPath("Opacity", 1));
            storyboard.Children.Add(fadeInAnimation);
            storyboard.Begin(MainScrollViewer);
        }
    }
}