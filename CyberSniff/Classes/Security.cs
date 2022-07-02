using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace CyberSniff.Classes
{
    public static class Security
    {
        private const string SettingsKey =
            "jRKmBBi1BHzCXHreFmD4VJD4aFBmgbKyVnmQFE6RMqdntR9RL7SbxFkx527yn4vp12PhWDNHHM6iIFf9b7oAr37Cb8427UUbJmGMotSqLkDPLN7amb4kOmxClZKdNtED";

        public static string Decrypt(string input)
        {
            try
            {
                input = input.Replace(" ", "+");
                var cipherBytes = Convert.FromBase64String(input);
                using var encryptor = Aes.Create();
                Rfc2898DeriveBytes pdb = new(SettingsKey,
                    new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using MemoryStream ms = new();
                using CryptoStream cs = new(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write);
                cs.Write(cipherBytes, 0, cipherBytes.Length);
                cs.Close();
                input = Encoding.Unicode.GetString(ms.ToArray());
                return input;
            }
            catch (Exception e)
            {
                _ = e.AutoDumpExceptionAsync();
                return JsonConvert.SerializeObject(new {error = "Encryption failed"});
            }
        }

        public static async Task<string> DecryptAsync(string input)
        {
            try
            {
                input = input.Replace(" ", "+");
                var cipherBytes = Convert.FromBase64String(input);
                using var encryptor = Aes.Create();
                Rfc2898DeriveBytes pdb = new(SettingsKey,
                    new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                await using MemoryStream ms = new();
                await using CryptoStream cs = new(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write);
                await cs.WriteAsync(cipherBytes.AsMemory(0, cipherBytes.Length));
                cs.Close();
                input = Encoding.Unicode.GetString(ms.ToArray());
                return input;
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return JsonConvert.SerializeObject(new {error = "Encryption failed"});
            }
        }

        public static async Task<string> DecryptThemeAsync(string input)
        {
            try
            {
                input = input.Replace(" ", "+");
                var cipherBytes = Convert.FromBase64String(input);
                using var encryptor = Aes.Create();
                const string key = "Kbs8WST6xEenNSZr3Sn22SsDCDHVQbaSAxhUmEPr7H4YQWbgaLpMMN37ZeByegxyYvLAPv8VUhxquZUuZz5n8D8Mm3r4DyFNS9aY9b88fU93VUtadJNz5eAX2WE2XVXG";
                Rfc2898DeriveBytes pdb = new(key,
                    new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                await using MemoryStream ms = new();
                await using CryptoStream cs = new(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write);
                await cs.WriteAsync(cipherBytes.AsMemory(0, cipherBytes.Length));
                cs.Close();
                input = Encoding.Unicode.GetString(ms.ToArray());
                return input;
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return JsonConvert.SerializeObject(new {error = "Encryption failed"});
            }
        }

        public static string Encrypt(string input)
        {
            try
            {
                var clearBytes = Encoding.Unicode.GetBytes(input);
                using var encryptor = Aes.Create();
                Rfc2898DeriveBytes pdb = new(SettingsKey,
                    new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using MemoryStream ms = new();
                using CryptoStream cs = new(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write);
                cs.Write(clearBytes, 0, clearBytes.Length);
                cs.Close();
                input = Convert.ToBase64String(ms.ToArray());
                return input;
            }
            catch (Exception e)
            {
                _ = e.AutoDumpExceptionAsync();
                return JsonConvert.SerializeObject(new {error = "Encryption failed"});
            }
        }

        public static async Task<string> EncryptAsync(string input)
        {
            try
            {
                var clearBytes = Encoding.Unicode.GetBytes(input);
                using var encryptor = Aes.Create();
                Rfc2898DeriveBytes pdb = new(SettingsKey,
                    new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                await using MemoryStream ms = new();
                await using CryptoStream cs = new(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write);
                await cs.WriteAsync(clearBytes.AsMemory(0, clearBytes.Length));
                cs.Close();
                input = Convert.ToBase64String(ms.ToArray());
                return input;
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return JsonConvert.SerializeObject(new {error = "Encryption failed"});
            }
        }

        public static async Task<string> EncryptThemeAsync(string input)
        {
            try
            {
                var clearBytes = Encoding.Unicode.GetBytes(input);
                using var encryptor = Aes.Create();
                const string key = "Kbs8WST6xEenNSZr3Sn22SsDCDHVQbaSAxhUmEPr7H4YQWbgaLpMMN37ZeByegxyYvLAPv8VUhxquZUuZz5n8D8Mm3r4DyFNS9aY9b88fU93VUtadJNz5eAX2WE2XVXG";
                Rfc2898DeriveBytes pdb = new(key,
                    new byte[] {0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76});
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                await using MemoryStream ms = new();
                await using CryptoStream cs = new(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write);
                cs.Write(clearBytes, 0, clearBytes.Length);
                cs.Close();
                input = Convert.ToBase64String(ms.ToArray());
                return input;
            }
            catch (Exception e)
            {
                await e.AutoDumpExceptionAsync();
                return JsonConvert.SerializeObject(new {error = "Encryption failed"});
            }
        }
    }
}