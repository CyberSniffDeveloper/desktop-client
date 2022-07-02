using System.ComponentModel;
using System.Net;
using MaterialDesignThemes.Wpf;

namespace CyberSniff.Models;

public struct CaptureGrid : INotifyPropertyChanged
{
    private string city;

    private string country;

    private PackIconKind ddosProtected;

    private string flag;

    private readonly IPAddress ipAddress;

    private string isp;

    private string label;

    private readonly ushort port;

    private string protocol;

    private PackIconKind spoofed;

    private string state;

    public event PropertyChangedEventHandler PropertyChanged;

    public string City
    {
        get => city;

        set
        {
            city = value;
            OnPropertyChanged(nameof(City));
        }
    }

    public string Country
    {
        get => country;

        set
        {
            country = value;
            OnPropertyChanged(nameof(Country));
        }
    }

    public PackIconKind DDoSProtected
    {
        get => ddosProtected;

        set
        {
            ddosProtected = value;
            OnPropertyChanged(nameof(DDoSProtected));
        }
    }

    public string Flag
    {
        get => flag;

        set
        {
            flag = value;
            OnPropertyChanged(nameof(Flag));
        }
    }

    public IPAddress IpAddress
    {
        get => ipAddress;

        init
        {
            ipAddress = value;
            OnPropertyChanged(nameof(IpAddress));
        }
    }

    public string Isp
    {
        get => isp;

        set
        {
            isp = value;
            OnPropertyChanged(nameof(Isp));
        }
    }

    public string Label
    {
        get => label;

        set
        {
            label = value;
            OnPropertyChanged(nameof(Label));
        }
    }

    public ushort Port
    {
        get => port;

        init
        {
            port = value;
            OnPropertyChanged(nameof(Port));
        }
    }

    public string Protocol
    {
        get => protocol;

        set
        {
            protocol = value;
            OnPropertyChanged(nameof(Protocol));
        }
    }

    public PackIconKind Spoofed
    {
        get => spoofed;

        set
        {
            spoofed = value;
            OnPropertyChanged(nameof(Spoofed));
        }
    }

    public string State
    {
        get => state;

        set
        {
            state = value;
            OnPropertyChanged(nameof(State));
        }
    }

    private void OnPropertyChanged(string propertyName)
    {
        var saved = PropertyChanged;
        if (saved == null) return;

        var e = new PropertyChangedEventArgs(propertyName);
        saved(this, e);
    }
}