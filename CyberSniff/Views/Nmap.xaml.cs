using System;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;

namespace CyberSniff.Views
{
    public partial class Nmap : Page
    {
        public Nmap(IPAddress host)
        {
            InitializeComponent();
            MainScrollViewer.Visibility = Visibility.Hidden;
            Loaded += (_, _) =>
            {
                IpAddressTitle.Text = $"{host}";
            };
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