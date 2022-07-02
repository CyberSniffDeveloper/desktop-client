using System.Threading.Tasks;
using CyberSniff.Models;

namespace CyberSniff.Interfaces
{
    internal interface IErrorLogging
    {
        Task<bool> WriteToLogAsync(string buffer, LogLevel logType);
    }
}