using System.Windows.Controls;
using CyberSniff.Models;

namespace CyberSniff.Views
{
    public partial class AdapterInfo : Page
    {
        public AdapterInfo(Adapter adapterInfo)
        {
            InitializeComponent();
            AdapterBufferSizeText.Text = $"Kernel buffer size: {adapterInfo.KernelBufferSize}";
            AdapterFlagsText.Text = $"Flags: {adapterInfo.Flags.Value}";
            AdapterFriendlyNameText.Text = $"Friendly Name: {adapterInfo.FriendlyName ?? "N/A"}";
            AdapterGatewayText.Text = $"Gateway: {adapterInfo.GatewayAddress ?? "N/A"}";
            AdapterIpAddressText.Text = $"Local Address: {adapterInfo.IpAddress ?? "N/A"}";
            AdapterLoopbackText.Text = $"Loopback: {adapterInfo.Loopback}";
            AdapterPointerText.Text = $"Pcap Handle: 0x{adapterInfo.PcapHandle.ToString("x") ?? "N/A"}";
            AdapterMacAddressText.Text = $"MAC Address: {adapterInfo.MacAddress}";
            AdapterHardwareAddressText.Text = $"H/W Address: {adapterInfo.Name ?? "N/A"}";
            AdapterLinkTypeText.Text = $"Link type: {adapterInfo.LinkType.Value}";
        }
    }
}