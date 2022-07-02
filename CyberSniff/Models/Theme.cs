using System.Windows.Media;

namespace CyberSniff.Models
{
    public struct Theme
    {
        public Color CustomColorBrush { init; get; }

        public bool DarkMode { init; get; }

        public ColorType PrimaryColor { init; get; }

        public ColorType SecondaryColor { init; get; }
    }
}