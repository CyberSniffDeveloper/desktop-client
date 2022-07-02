using Newtonsoft.Json;

namespace CyberSniff.Models
{
    public class GeolocationResponse
    {
        [JsonProperty("as")] public string Asn { get; set; }

        [JsonProperty("city")] public string City { get; set; }

        [JsonProperty("continent")] public string Continent { get; set; }

        [JsonProperty("country")] public string Country { get; set; }

        [JsonProperty("countryCode")] public string CountryCode { get; set; }

        [JsonProperty("reverse")] public string Hostname { get; set; }

        [JsonProperty("hosting")] public bool IsHosting { get; set; }

        [JsonProperty("mobile")] public bool IsHotspot { get; set; }

        [JsonProperty("isp")] public string Isp { get; set; }

        [JsonProperty("proxy")] public bool IsProxy { get; set; }

        [JsonProperty("lat")] public string Latitude { get; set; }

        [JsonProperty("lon")] public string Longitude { get; set; }

        [JsonProperty("org")] public string Organization { get; set; }

        [JsonProperty("regionName")] public string Region { get; set; }

        [JsonProperty("timezone")] public string Timezone { get; set; }

        [JsonProperty("zip")] public string Zip { get; set; }
    }
}