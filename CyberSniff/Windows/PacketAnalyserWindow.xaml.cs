using System;
using System.ComponentModel;
using System.IO;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using Microsoft.Win32;
using PacketDotNet;
using SharpPcap.LibPcap;

namespace CyberSniff.Windows
{
    public partial class PacketAnalyserWindow : Window
    {
        private readonly Packet packet;

        private bool closeStoryBoardCompleted;

        public PacketAnalyserWindow(Packet packet, ImageSource backgroundBm, PhysicalAddress hostAddr)
        {
            InitializeComponent();
            TitleBox.Text = $"CyberSniff-OSS v{Assembly.GetExecutingAssembly().GetCyberSniffVersion()} - Packet Analyser";
            this.packet = packet;
            if (backgroundBm != null) BackgroundImage.Source = backgroundBm;
            MainContent.Text = packet.PrintHex();
            var tcpPacket = packet.Extract<TcpPacket>();
            var udpPacket = packet.Extract<UdpPacket>();
            var ethPacket = packet.Extract<EthernetPacket>();
            if (tcpPacket != null)
            {
                var ipPacket = (IPPacket) tcpPacket.ParentPacket;
                ParsedContent.Text +=
                    $"[Eth]\n Source hardware address: {ethPacket.SourceHardwareAddress}\n Destination hardware address: {ethPacket.DestinationHardwareAddress}\n Host hardware address: {hostAddr}\n[Packet]\r\n Packet Length: {packet.TotalPacketLength}\r\n PayloadInitialized: {packet.IsPayloadInitialized}\r\n[Extracted Packet]\r\n Protocol: Transmission Control Protocol\r\n Dest Port: {tcpPacket.DestinationPort}\r\n Src Port: {tcpPacket.SourcePort}\r\n Acknowledged: {tcpPacket.Acknowledgment}\r\n Checksum: {tcpPacket.Checksum}\r\n Flags: {tcpPacket.Flags}\r\n ValidTcpChecksum: {tcpPacket.ValidTcpChecksum}\r\n Urgent: {tcpPacket.Urgent}\r\n[IPPacket]\r\n Dest Address: {ipPacket.DestinationAddress}\r\n IPv: {ipPacket.Version}\r\n Src Address: {ipPacket.SourceAddress}\r\n Proto: {ipPacket.Protocol}\r\n TTL: {ipPacket.TimeToLive}";
            }
            else if (udpPacket != null)
            {
                var ipPacket = (IPPacket) udpPacket.ParentPacket;
                ParsedContent.Text +=
                    $"[Eth]\n Source hardware address: {ethPacket.SourceHardwareAddress}\n Destination hardware address: {ethPacket.DestinationHardwareAddress}\n Host hardware address: {hostAddr}\n[Packet]\r\n Packet Length: {packet.TotalPacketLength}\r\n PayloadInitialized: {packet.IsPayloadInitialized}\r\n[Extracted Packet]\r\n Protocol: User Datagram Protocol\r\n Dest Port: {udpPacket.DestinationPort}\r\n Src Port: {udpPacket.SourcePort}\r\n Checksum: {udpPacket.Checksum}\r\n ValidUdpChecksum: {udpPacket.ValidUdpChecksum}\r\n[IPPacket]\r\n Dest Address: {ipPacket.DestinationAddress}\r\n IPv: {ipPacket.Version}\r\n Src Address: {ipPacket.SourceAddress}\r\n Proto: {ipPacket.Protocol}\r\n TTL: {ipPacket.TimeToLive}";
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            CloseButton.IsEnabled = true;
            Close();
        }

        private async void HandleMenuItems(object sender, RoutedEventArgs e)
        {
            if (sender is not MenuItem menu) return;
            
            switch (menu.Name)
            {
                case "CopyPayloadMenu":
                    if (!string.IsNullOrWhiteSpace(MainContent.Text)) MainContent.Text.CopyToClipboard();
                    break;

                case "ExportAsPcapMenu":
                    await Task.Run(async () =>
                    {
                        SaveFileDialog sfd = new()
                        {
                            Filter = "Pcap file (*.pcap) | *.pcap",
                            Title = "Export as pcap...",
                            CheckPathExists = true,
                            ValidateNames = true,
                            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
                        };
                        if (sfd.ShowDialog() == true)
                        {
                            CaptureFileWriterDevice captureFileWriter = new(sfd.FileName);
                            captureFileWriter.Write(packet.Bytes);
                            await Dispatcher.InvokeAsync(() =>
                            {
                                Globals.Container.GetInstance<IThemeUtils>().MsgBox(new MsgBox
                                {
                                    Button = MsgBox.MsgBoxBtn.Ok, Icon = MsgBox.MsgBoxIcon.Success,
                                    Message =
                                        $"Successfully wrote {packet.Bytes.Length} packet bytes to {Path.GetFileName(sfd.FileName)}"
                                });
                            });
                        }
                    });
                    break;
            }
        }
        
        private void Storyboard_Completed(object sender, EventArgs e)
        {
            closeStoryBoardCompleted = true;
            Close();
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            if (closeStoryBoardCompleted) return;
            
            var sb = FindResource("CloseAnim") as BeginStoryboard;
            sb?.Storyboard.Begin();
            e.Cancel = true;
        }
    }
}