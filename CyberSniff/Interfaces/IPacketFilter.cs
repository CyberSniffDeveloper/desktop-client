using CyberSniff.Models;
using System.Threading.Tasks;

namespace CyberSniff.Interfaces
{
    internal interface IPacketFilter
    {
        public Task<bool> FilterPacketAsync(PacketWrapper wrapper);
    }
}