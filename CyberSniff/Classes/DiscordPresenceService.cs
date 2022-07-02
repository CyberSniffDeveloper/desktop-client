using System;
using System.IO;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using DiscordRPC;
using DiscordRPC.Logging;

namespace CyberSniff.Classes
{
    public sealed class DiscordPresenceService : IDiscordPresenceService
    {
        private readonly DiscordPresenceConfiguration configuration;
        private DiscordRpcClient client;

        public DiscordPresenceService(DiscordPresenceConfiguration configuration)
        {
            this.configuration = configuration;

            if (!Directory.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "CSniffOSS")))
            {
                Directory.CreateDirectory(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CSniffOSS"));
            }

            CreateInstance();
        }

        public RichPresence Presence { get; set; }

        public void CreateInstance()
        {
            client = new DiscordRpcClient(configuration.ClientId.ToString(),
                logger: new FileLogger(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CSniffOSS", "discord.log")));

            Presence = GetRichPresence();
            client.SetPresence(Presence);
        }

        public RichPresence GetRichPresence()
        {
            return new RichPresence
            {
                State = "Idle",
                Assets = new Assets
                {
                    LargeImageKey = configuration.LargeImageKey,
                    LargeImageText = configuration.LargeImageText
                }
            };
        }

        public void ResetPresence()
        {
            Presence = GetRichPresence();
        }

        public void Dispose()
        {
            ClearPresence();
            DeInitialize();
            client.Dispose();
        }

        public void ClearPresence()
        {
            client.ClearPresence();
        }

        public void DeInitialize()
        {
            if (!client.IsInitialized) return;

            client.Deinitialize();
            client.Dispose();
        }

        public void Initialize()
        {
            if (!client.IsInitialized || client.IsDisposed)
            {
                CreateInstance();
                client.Initialize();
            }

            SetPresence();
        }

        public void ResetTimestamps()
        {
            Presence.WithTimestamps(null);

            SetPresence();
        }

        public void UpdateDetails(string details)
        {
            Presence.WithDetails(details);

            SetPresence();
        }

        public void UpdateState(string state)
        {
            Presence.WithState(state);

            SetPresence();
        }

        public void UpdateTimestamps()
        {
            Presence.WithTimestamps(new Timestamps(DateTime.UtcNow));

            SetPresence();
        }

        public void SetPresence()
        {
            if (!client.IsInitialized) return;

            client.SetPresence(Presence);
        }
    }
}