using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Windows;
using CyberSniff.Classes;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using SimpleInjector;

namespace CyberSniff
{
    public partial class App : Application
    {
        public App()
        {
            Globals.Container.Register<IPacketFilter, PacketFilter>(Lifestyle.Singleton);
            Globals.Container.Register<IThemeUtils, ThemeUtils>(Lifestyle.Singleton);
            Globals.Container.RegisterSingleton<IDiscordPresenceService>(() => new DiscordPresenceService(
                new DiscordPresenceConfiguration
                {
                    ClientId = 992863681488633896,
                    LargeImageKey = "main",
                    LargeImageText = $"CyberSniff [version {Assembly.GetExecutingAssembly().GetName().Version} OSS STABLE]"
                }));
            Globals.Container.Register<IExportDrawer, ExportDrawer>(Lifestyle.Singleton);
            Globals.Container.Register<IServerSettings, ServerSettings>(Lifestyle.Singleton);
            Globals.Container.Register<IErrorLogging, ErrorLogging>(Lifestyle.Singleton);
            Globals.Container.RegisterSingleton<ICacheManager<List<GeolocationCache>>>(() => new CacheManager<List<GeolocationCache>>(new CacheConfiguration
            {
                FilePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "CSniffOSS", "geo.bin")
            }));
            Globals.Container.Register(() => new HttpClient(), Lifestyle.Singleton);

            Globals.Container.Verify();
            
            // Gets the settings
            Globals.Container.GetInstance<IServerSettings>().GetSettingsAsync();
        }
    }
}