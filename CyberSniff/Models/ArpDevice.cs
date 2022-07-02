using System.Net;
using System.Net.NetworkInformation;

namespace CyberSniff.Models;

public struct ArpDevice
{
    public bool IsNullRouted { init; get; }

    public IPAddress SourceLocalAddress { init; get; }

    public PhysicalAddress SourcePhysicalAddress { init; get; }

    public IPAddress TargetLocalAddress { get; init; }

    public PhysicalAddress TargetPhysicalAddress { init; get; }
}