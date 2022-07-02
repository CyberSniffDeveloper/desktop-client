using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using Newtonsoft.Json;

namespace CyberSniff.Classes
{
    public class ServerSettings : IServerSettings
    {
        public async void GetSettingsAsync()
        {
            var fileLocation = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CSniffOSS", "settings.bin");
            if (!File.Exists(fileLocation))
            {
                if (!Directory.Exists(Path.GetDirectoryName(fileLocation)))
                    Directory.CreateDirectory(Path.GetDirectoryName(fileLocation));
                
                Globals.Settings = new Settings();
                await UpdateSettingsAsync();
            }
            
            var contents = await File.ReadAllTextAsync(fileLocation);

            var decryptedContents = await Security.DecryptAsync(contents);

            var jsonResp = JsonConvert.DeserializeObject<Settings>(decryptedContents);

            Globals.Settings = jsonResp;
        }

        [Obfuscation(Feature = "virtualization", Exclude = false)]
        public async Task<bool> UpdateSettingsAsync()
        {
            var newSettings = new Settings
            {
                PacketAnalyser = Globals.Settings.PacketAnalyser,
                ShowFlags = Globals.Settings.ShowFlags,
                AutoShowPanel = Globals.Settings.AutoShowPanel,
                DiscordStatus = Globals.Settings.DiscordStatus,
                Background = Globals.Settings.Background,
                ColorType = Globals.Settings.ColorType,
                DynamicRemove = Globals.Settings.DynamicRemove,
                EnableLabels = Globals.Settings.EnableLabels,
                Filter = Globals.Settings.Filter,
                Geolocate = Globals.Settings.Geolocate,
                HardwareAccel = Globals.Settings.HardwareAccel,
                HexColor = Globals.Settings.HexColor,
                HideInterfaces = Globals.Settings.HideInterfaces,
                InterfaceName = Globals.Settings.InterfaceName,
                Labels = Globals.Settings.Labels,
                Ports = Globals.Settings.Ports,
                PortsInverse = Globals.Settings.PortsInverse,
                RememberInterface = Globals.Settings.RememberInterface,
                TopMost = Globals.Settings.TopMost
            };
            var json = JsonConvert.SerializeObject(newSettings);
            var encryptedJson = await Security.EncryptAsync(json);

            await File.WriteAllTextAsync(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CSniffOSS", "settings.bin"),
                encryptedJson);
            
            return true;
        }
    }
}