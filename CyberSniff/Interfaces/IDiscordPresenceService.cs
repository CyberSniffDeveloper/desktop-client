using System;
using DiscordRPC;

namespace CyberSniff.Interfaces
{
    public interface IDiscordPresenceService
    {
        RichPresence Presence { get; set; }
        void CreateInstance();
        RichPresence GetRichPresence();
        void ResetPresence();
        void Dispose();
        void ClearPresence();
        void DeInitialize();
        void Initialize();
        void ResetTimestamps();
        void UpdateDetails(string details);
        void UpdateState(string state);
        void UpdateTimestamps();
        void SetPresence();
    }
}