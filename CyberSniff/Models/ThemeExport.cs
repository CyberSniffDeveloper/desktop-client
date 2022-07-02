namespace CyberSniff.Models
{
    public struct ThemeExport
    {
        public string Author { get; set; }

        public string BackgroundFileName { get; init; }

        public byte[] PictureBytes { get; init; }

        public Theme ThemeObject { get; init; }
    }
}