using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using PacketDotNet;
using SharpPcap.Npcap;

namespace CyberSniff
{
    public static class Extensions
    {
        public static async Task<bool> CheckAndForwardPacketAsync(Packet packet, NpcapDevice device,
            PhysicalAddress targetPhysicalAddress, PhysicalAddress realGatewayAddress)
        {
            try
            {
                if (!device.Opened)
                    device.Open();

                var ethPacket = packet.Extract<EthernetPacket>();

                if (ethPacket == null || device.MacAddress == null) return false;

                if (!ethPacket.SourceHardwareAddress.ToString().Contains(targetPhysicalAddress.ToString()))
                    return false;
                ethPacket.DestinationHardwareAddress = realGatewayAddress;

                return true;

            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return false;
            }
        }

        public static bool CheckRemoteAddr(this string remoteAddr)
        {
            if (IPAddress.TryParse(remoteAddr, out var address))
                return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ||
                       address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
            return false;
        }

        public static async void CopyToClipboard(this string text)
        {
            try
            {
                Clipboard.SetText(text);
            }
            catch (Exception ex)
            {
                await ex.AutoDumpExceptionAsync();
                MessageBox.Show($"Failed to copy to clipboard\n\nWhat happened: {ex.Message}", "CyberSniff",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        public static AddressFamily GetAddressFamily(this NpcapDevice device)
        {
            string interfaceLocalAddress;
            if (device.Addresses.Any())
            {
                interfaceLocalAddress = device.Addresses.First().Addr.ToString();
                if (interfaceLocalAddress == "0.0.0.0") return AddressFamily.Null;
            }
            else
            {
                return AddressFamily.Null;
            }

            if (string.IsNullOrWhiteSpace(interfaceLocalAddress)) return AddressFamily.Null;
            return interfaceLocalAddress.Contains(':') ? AddressFamily.IPv6 : AddressFamily.IPv4;
        }

        public static Version GetCyberSniffVersion(this Assembly assembly)
        {
            var fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            return Version.Parse(fvi.FileVersion);
        }

        public static string GetCyberSniffVersionString(this Assembly assembly)
        {
            var fvi = FileVersionInfo.GetVersionInfo(assembly.Location);
            return fvi.FileVersion.Replace(".0", "");
        }

        public static async Task<bool> AutoDumpExceptionAsync(this Exception exception)
        {
            return await Globals.Container.GetInstance<IErrorLogging>().WriteToLogAsync(
                $"Exception thrown on {exception.Source} at {exception.TargetSite}: {exception.Message}. Trace:\n\n{exception.StackTrace}\r\n",
                LogLevel.ERROR);
        }
        
        public static async Task PoisonAsync(this NpcapDevice device, IPAddress targetAddress,
            PhysicalAddress targetMac, IPAddress gatewayIpAddress, PhysicalAddress gatewayMacAddress)
        {
            try
            {
                if (!device.Opened)
                    device.Open();
                if (device.MacAddress == null || targetAddress == null || targetMac == null ||
                    gatewayIpAddress == null || gatewayMacAddress == null) return;
                ArpPacket arpPacket = new(ArpOperation.Request, targetMac, targetAddress,
                    device.MacAddress, gatewayIpAddress);
                EthernetPacket ethPacket = new(device.MacAddress, targetMac, EthernetType.Arp)
                {
                    PayloadPacket = arpPacket
                };
                await Task.Run(() => device.SendPacket(ethPacket));
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
            }
        }

        public static async Task<bool> ValidateIpAsync(this string ip)
        {
            try
            {
                await Dns.GetHostAddressesAsync(ip);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static string ToHex(this Color c)
        {
            return $"#{c.R:X2}{c.G:X2}{c.B:X2}";
        }
    }
}