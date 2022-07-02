using CyberSniff.Models;
using System.Threading.Tasks;

namespace CyberSniff.Interfaces
{
    public interface IServerSettings
    {
        void GetSettingsAsync();

        Task<bool> UpdateSettingsAsync();
    }
}