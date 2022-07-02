using Newtonsoft.Json;

namespace CyberSniff.Models;

public class GeolocationCache : GeolocationResponse
{
    [JsonProperty("ip_address")] public string IpAddress { get; set; }

    public void ConstructFromGeolocationResponse(GeolocationResponse response)
    {
        Isp = response.Isp;
        Asn = response.Asn;
        Hostname = response.Hostname;
        Region = response.Region;
        Isp = response.Isp;
        IsHosting = response.IsHosting;
        IsHotspot = response.IsHotspot;
        IsProxy = response.IsProxy;
        Organization = response.Organization;
        Continent = response.Continent;
        Country = response.Country;
        CountryCode = response.CountryCode;
        City = response.City;
        Latitude = response.Latitude;
        Longitude = response.Longitude;
        Zip = response.Zip;
        Timezone = response.Timezone;
    }
}