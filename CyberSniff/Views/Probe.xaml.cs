using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;

namespace CyberSniff.Views
{
    public partial class Probe : Page
    {
        public Probe(IPAddress host, ushort port)
        {
            InitializeComponent();
            MainScrollViewer.Visibility = Visibility.Hidden;
            Loaded += async (_, _) =>
            {
                host = host ?? throw new ArgumentNullException(nameof(host));
                TitleTextBlock.Text = $"{host}:{port}";
                using var tcpClient = new TcpClient
                {
                    ReceiveTimeout = 2000,
                    SendTimeout = 2000,
                    SendBufferSize = 100,
                    ExclusiveAddressUse = true,
                    LingerState = new LingerOption(false, 0),
                    NoDelay = true,
                    Client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
                    {
                        ReceiveTimeout = 2000,
                        SendTimeout = 2000,
                        SendBufferSize = 100
                    }
                };
                Stopwatch stopWatch = new();
                stopWatch.Start();
                try
                {
                    await Task.Run(async () =>
                    {
                        if (!tcpClient.ConnectAsync(host, port).Wait(2000))
                            await Dispatcher.InvokeAsync(() =>
                            {
                                StatusText.Text = "Status: connection refused / timed out";
                            });
                        else
                            await Dispatcher.InvokeAsync(() => { StatusText.Text = "Status: connected!"; });
                    });
                }
                catch (Exception)
                {
                    StatusText.Text = "Status: connection refused / timed out";
                }
                finally
                {
                    stopWatch.Stop();
                    ConnectTimeText.Text = $"Time: {stopWatch.ElapsedMilliseconds}ms";
                    FragmentedText.Text = "Fragmented: yes";
                    tcpClient.Dispose();
                    stopWatch.Reset();
                    PlayAnim();
                }
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