using CyberSniff.Models;
using SimpleInjector;

namespace CyberSniff
{
    public static class Globals
    {
        public static readonly Container Container = new();

        public static Settings Settings;
    }
}