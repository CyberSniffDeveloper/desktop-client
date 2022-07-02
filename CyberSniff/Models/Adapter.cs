using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Windows;
using CyberSniff.Properties;
using PacketDotNet;
using SharpPcap;
using SharpPcap.Npcap;

namespace CyberSniff.Models;

public struct Adapter
{

    public static readonly HashSet<Adapter> Instance = new();

    public AddressFamily AddressFamily { get; set; }

    public string DisplayName { get; private init; }

    public uint? Flags { get; private init; }

    public string FriendlyName { get; private init; }

    public string GatewayAddress { get; private init; }

    public string IpAddress { get; private init; }

    public ushort? KernelBufferSize { get; private init; }

    public LinkLayers? LinkType { get; private init; }

    public bool? Loopback { get; private init; }

    public PhysicalAddress MacAddress { get; private init; }

    public string Name { get; private init; }

    public IntPtr PcapHandle { get; private init; }

    public static async Task InitAdapters()
    {
        try
        {
            Instance.Clear();
            var devices = CaptureDeviceList.Instance.ToList();
            foreach (var dev in devices)
                try
                {
                    dev.Open();
                    var npcapInterface = (NpcapDevice) dev;
                    if (string.IsNullOrWhiteSpace(npcapInterface.Name) ||
                        string.IsNullOrWhiteSpace(npcapInterface.Interface.FriendlyName)) continue;
                    if (Globals.Settings.HideInterfaces && string.IsNullOrWhiteSpace(dev.Description)) continue;

                    string interfaceLocalAddress;

                    if (npcapInterface.Addresses.Any())
                    {
                        interfaceLocalAddress = npcapInterface.Addresses.First().Addr.ToString();
                        if (interfaceLocalAddress == "0.0.0.0") interfaceLocalAddress = "N/A";
                    }
                    else
                    {
                        interfaceLocalAddress = "N/A";
                    }

                    var gatewayAddress = npcapInterface.Interface.GatewayAddresses.Any()
                        ? npcapInterface.Interface.GatewayAddresses.First().ToString()
                        : "N/A";

                    if (string.IsNullOrWhiteSpace(interfaceLocalAddress) ||
                        !interfaceLocalAddress.CheckRemoteAddr()) interfaceLocalAddress = "N/A";
                    var obj = new Adapter
                    {
                        AddressFamily = npcapInterface.GetAddressFamily(),
                        FriendlyName = npcapInterface.Interface.FriendlyName,
                        DisplayName =
                            $"{npcapInterface.Interface.FriendlyName} - {npcapInterface.GetAddressFamily()}: {interfaceLocalAddress}",
                        Flags = npcapInterface.Flags, GatewayAddress = gatewayAddress,
                        IpAddress = interfaceLocalAddress, LinkType = npcapInterface.LinkType,
                        KernelBufferSize = 10240, Loopback = npcapInterface.Loopback,
                        PcapHandle = npcapInterface.PcapHandle, Name = npcapInterface.Name,
                        MacAddress = npcapInterface.MacAddress
                    };
                    Instance.Add(obj);
                }
                catch (Exception ex1)
                {
                    await ex1.AutoDumpExceptionAsync();
                    dev.Close();
                    MessageBox.Show($"{Resources.ADAPTER_EXCEPTION}\n\nWhat happened: {ex1.Message}", "CyberSniff",
                        MessageBoxButton.OK, MessageBoxImage.Warning);
                }
                finally
                {
                    dev.Close();
                }
        }
        catch (Exception ex)
        {
            if (ex.Message.ToLower().Contains("unable to load dll"))
            {
                await ex.AutoDumpExceptionAsync();
                MessageBox.Show(
                    $"{Resources.ADAPTER_EXCEPTION}\n\nYou will need to install Npcap for CyberSniff to work\n\nNeed help installing Npcap? Follow the setup guide at https://cybersniff.net/support/setup\n\nInstalled Npcap and CyberSniff is still not working?\nReport this to us: failed to load dynamic link library. Npcap capture driver was not found or corrupt.",
                    "CyberSniff", MessageBoxButton.OK, MessageBoxImage.Warning);
                Environment.Exit(0);
                return;
            }

            await ex.AutoDumpExceptionAsync();
        }

        if (Instance.Count == 0)
        {
            MessageBox.Show(
                $"{Resources.ADAPTER_EXCEPTION}\n\nYou will need to install Npcap for CyberSniff to work\n\nNeed help installing Npcap? Follow the setup guide at https://cybersniff.net/support/setup\n\nInstalled Npcap and CyberSniff is still not working?\nReport this to us: detected 0 adapters from capturedevicelist instance.",
                "CyberSniff", MessageBoxButton.OK, MessageBoxImage.Warning);
            Environment.Exit(0);
        }
    }
}