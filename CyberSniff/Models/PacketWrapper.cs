using PacketDotNet;
using SharpPcap;

namespace CyberSniff.Models
{
    public struct PacketWrapper
    {
        public RawCapture p;

        public PacketWrapper(int count, RawCapture p)
        {
            Count = count;
            this.p = p;
        }

        public int Count { get; }

        public LinkLayers LinkLayerType => p.LinkLayerType;

        public Packet Packet => Packet.ParsePacket(p.LinkLayerType, p.Data);

        public ProtocolType Protocol
        {
            get
            {
                var packet = Packet.ParsePacket(LinkLayerType, p.Data);
                var ipPacket = packet.Extract<IPPacket>();
                return ipPacket?.Protocol ?? ProtocolType.Reserved254;
            }
        }

        public PosixTimeval TimeValue => p.Timeval;
    }
}