using System.IO;
using CyberSniff.Interfaces;
using CyberSniff.Models;
using Newtonsoft.Json;

namespace CyberSniff.Classes;

public class CacheManager<T> : ICacheManager<T>
{
    private readonly CacheConfiguration configuration;
    private readonly object threadLock = new();

    public CacheManager(CacheConfiguration configuration)
    {
        this.configuration = configuration;
    }

    public void ClearCache()
    {
        lock (threadLock)
        {
            File.Delete(configuration.FilePath);
        }
    }

    public T GetCache()
    {
        lock (threadLock)
        {
            if (!File.Exists(configuration.FilePath)) return default;

            var fileBytes = File.ReadAllText(configuration.FilePath);
            var decryptedBytes = Security.Decrypt(fileBytes);

            return JsonConvert.DeserializeObject<T>(decryptedBytes);
        }
    }

    public void WriteCache(T cache)
    {
        lock (threadLock)
        {
            var json = JsonConvert.SerializeObject(cache);
            var encryptedJson = Security.Encrypt(json);

            File.WriteAllText(configuration.FilePath, encryptedJson);
        }
    }
}