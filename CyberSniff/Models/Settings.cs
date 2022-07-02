using System.Collections.Generic;
using Newtonsoft.Json;

namespace CyberSniff.Models
{
    public class Settings
    {
        [JsonProperty("AutoShowPanel")] public bool AutoShowPanel { get; set; } = true;

        [JsonProperty("Background")] public string Background { get; set; } = "None";

        [JsonProperty("ColorType")] public ColorType ColorType { get; set; } = ColorType.Default;

        [JsonProperty("DiscordStatus")] public bool DiscordStatus { get; set; } = true;

        [JsonProperty("Dynamic Remove")] public bool DynamicRemove { get; set; } = true;

        [JsonProperty("EnableLabels")] public bool EnableLabels { get; set; }

        [JsonProperty("Filter")] public FilterPreset Filter { get; set; } = FilterPreset.None;

        [JsonProperty("Geolocate")] public bool Geolocate { get; set; } = true;

        [JsonProperty("HardwareAccel")] public bool HardwareAccel { get; set; } = true;

        [JsonProperty("HexColor")] public string HexColor { get; set; } = "#ff5722";

        [JsonProperty("HideInvalidInterfaces")]
        public bool HideInterfaces { get; set; }

        [JsonProperty("InterfaceName")] public string InterfaceName { get; set; }

        [JsonProperty("Labels")] public List<Label> Labels { get; set; } = new();

        [JsonProperty("PacketAnalyser")] public bool PacketAnalyser { get; set; }

        [JsonProperty("Ports")] public List<ushort> Ports { get; set; } = new();

        [JsonProperty("PortsInverse")] public bool PortsInverse { get; set; }

        [JsonProperty("RememberInterface")] public bool RememberInterface { get; set; } = true;

        [JsonProperty("ShowFlags")] public bool ShowFlags { get; set; } = true;

        [JsonProperty("TopMost")] public bool TopMost { get; set; }
    }
}