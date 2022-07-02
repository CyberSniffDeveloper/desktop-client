using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Threading.Tasks;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using Newtonsoft.Json;

namespace CyberSniff.Classes
{
    public static class Web
    {
        private static readonly HttpClient Client;
        static Web()
        {
            HttpClientHandler httpClientHandler = new()
            {
                Proxy = null,
                UseProxy = false,
                UseCookies = false,
                AutomaticDecompression = DecompressionMethods.All,
            };
            Client = new HttpClient(httpClientHandler);
            Client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("CyberSniff",
                Assembly.GetCallingAssembly().GetName().Version?.ToString()));
        }

        public static async Task<GeolocationResponse> IpLocationAsync(IPAddress ip)
        {
            try
            {
                var geoCacheManager = Globals.Container.GetInstance<ICacheManager<List<GeolocationCache>>>();
                var geoCache = geoCacheManager.GetCache() ?? new List<GeolocationCache>();

                if (geoCache.Any(x => x.IpAddress == ip.ToString()))
                    return geoCache.FirstOrDefault(x => x.IpAddress == ip.ToString());

                var response = await Client.GetStringAsync($"http://ip-api.com/json/{ip}?fields=66846719");
                
                var json = JsonConvert.DeserializeObject<GeolocationResponse>(response);
                
                // Construct cache from the response
                var cache = new GeolocationCache
                {
                    IpAddress = ip.ToString()
                };
                cache.ConstructFromGeolocationResponse(json);

                // Add and write to the cache
                geoCache.Add(cache);
                geoCacheManager.WriteCache(geoCache);

                return json;
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return null;
            }
        }
    }
}