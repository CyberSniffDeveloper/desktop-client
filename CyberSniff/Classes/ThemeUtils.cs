using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using CyberSniff.Properties;
using CyberSniff.Windows;
using MaterialDesignThemes.Wpf;
using Newtonsoft.Json;
using Theme = CyberSniff.Models.Theme;

namespace CyberSniff.Classes
{
    public class ThemeUtils : IThemeUtils
    {
        public async Task ExportTheme(string path)
        {
            var obj = new Theme
            {
                CustomColorBrush = (Color) ColorConverter.ConvertFromString(Globals.Settings.HexColor), DarkMode = true,
                PrimaryColor = Globals.Settings.ColorType, SecondaryColor = Globals.Settings.ColorType
            };

            if (Globals.Settings.Background != "None")
            {
                var wpBytes =
                    await File.ReadAllBytesAsync(
                        Path.GetFullPath(Globals.Settings.Background)); // Reads all wallpaper bytes asynchronously

                var expObj1 = JsonConvert.SerializeObject(new ThemeExport
                {
                    ThemeObject = obj,
                    BackgroundFileName = Path.GetFileName(Globals.Settings.Background),
                    PictureBytes = wpBytes,
                    Author = Environment.UserName
                }, Formatting.None);

                await File.WriteAllTextAsync(path, await Security.EncryptThemeAsync(expObj1));
                return;
            }

            var expObj = JsonConvert.SerializeObject(new ThemeExport
            {
                ThemeObject = obj,
                Author = Environment.UserName
            }, Formatting.None);

            await File.WriteAllTextAsync(path, await Security.EncryptThemeAsync(expObj));
        }

        public async Task ImportTheme(string path)
        {
            var theme =
                JsonConvert.DeserializeObject<ThemeExport>(
                    await Security.DecryptThemeAsync(await File.ReadAllTextAsync(path)));
            Globals.Settings.ColorType = theme.ThemeObject.PrimaryColor;
            if (theme.BackgroundFileName != null)
            {
                var imagePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "CSniffOSS", "themes", "images", theme.BackgroundFileName);
                if (!Directory.Exists(Path.GetDirectoryName(imagePath)))
                    Directory.CreateDirectory(Path.GetDirectoryName(imagePath));
                if (!File.Exists(imagePath)) await File.WriteAllBytesAsync(imagePath, theme.PictureBytes);
                Globals.Settings.Background = imagePath;
            }
            else
            {
                Globals.Settings.Background = "None";
            }

            Globals.Settings.HexColor = theme.ThemeObject.CustomColorBrush.ToHex();
            SwitchTheme(new Theme
            {
                CustomColorBrush = (Color) ColorConverter.ConvertFromString(Globals.Settings.HexColor), DarkMode = true,
                PrimaryColor = Globals.Settings.ColorType, SecondaryColor = Globals.Settings.ColorType
            });
        }

        public bool IsImage(string filename)
        {
            try
            {
                _ = new BitmapImage(new Uri(filename));
            }
            catch (NotSupportedException)
            {
                return false;
            }

            return true;
        }

        public MsgBox.MsgBoxResult MsgBox(MsgBox m)
        {
            CustomMsgBox msgBox = null;
            var thread = new Thread(() =>
            {
                msgBox = new CustomMsgBox(m);
                msgBox.ShowDialog();
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join();
            return msgBox.Result;
        }

        public async void SwitchTheme(Theme colorObject)
        {
            try
            {
                var baseTheme = colorObject.DarkMode
                    ? MaterialDesignThemes.Wpf.Theme.Dark
                    : MaterialDesignThemes.Wpf.Theme.Light;
                switch (colorObject.PrimaryColor)
                {
                    case ColorType.Default:
                        ITheme defaultTheme3 = MaterialDesignThemes.Wpf.Theme.Create(baseTheme,
                            Color.FromRgb(255, 87, 34), Color.FromRgb(221, 44, 0));
                        Application.Current.Resources.SetTheme(defaultTheme3);
                        break;

                    case ColorType.Accent:
                        ITheme defaultTheme1 = MaterialDesignThemes.Wpf.Theme.Create(baseTheme,
                            SystemParameters.WindowGlassColor, SystemParameters.WindowGlassColor);
                        Application.Current.Resources.SetTheme(defaultTheme1);
                        break;

                    case ColorType.Custom:
                        ITheme defaultTheme2 = MaterialDesignThemes.Wpf.Theme.Create(baseTheme,
                            colorObject.CustomColorBrush, colorObject.CustomColorBrush);
                        Application.Current.Resources.SetTheme(defaultTheme2);
                        break;

                    default:
                        var pColor = (Color) ColorConverter.ConvertFromString(colorObject.PrimaryColor.ToString());
                        var sColor = (Color) ColorConverter.ConvertFromString(colorObject.SecondaryColor.ToString());
                        ITheme theme = MaterialDesignThemes.Wpf.Theme.Create(baseTheme, pColor, sColor);
                        Application.Current.Resources.SetTheme(theme);
                        break;
                }
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                MessageBox.Show($"{Resources.GENERIC_EXCEPTION}\n\nWhat happened: {e.Message}", "CyberSniff",
                    MessageBoxButton.OK, MessageBoxImage.Warning);

                Environment.Exit(0);
            }
        }
    }
}