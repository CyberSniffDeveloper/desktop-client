using System.Linq;
using System.Threading.Tasks;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using PacketDotNet;

namespace CyberSniff.Classes
{
    public class PacketFilter : IPacketFilter
    {
        public Task<bool> FilterPacketAsync(PacketWrapper packetWrapper)
        {
            var packet = packetWrapper.Packet.Extract<IPPacket>();
            return Task.FromResult(packet is not null);
        }
    }
}