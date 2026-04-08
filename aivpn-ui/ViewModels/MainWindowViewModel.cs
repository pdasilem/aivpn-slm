using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Aivpn.Ui.Models;
using Aivpn.Ui.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace Aivpn.Ui.ViewModels;

public partial class MainWindowViewModel : ViewModelBase
{
    private readonly IClientService clientService;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand))]
    [NotifyCanExecuteChangedFor(nameof(DeleteProfileCommand))]
    private ConnectionProfile? selectedProfile;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveProfileCommand))]
    private string profileName = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(SaveProfileCommand))]
    private string connectionKey = string.Empty;

    [ObservableProperty]
    private bool fullTunnel = true;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ConnectCommand))]
    [NotifyCanExecuteChangedFor(nameof(DisconnectCommand))]
    private bool isConnected;

    [ObservableProperty]
    private string statusText = "Disconnected";

    [ObservableProperty]
    private long bytesSent;

    [ObservableProperty]
    private long bytesReceived;

    [ObservableProperty]
    private string logText = string.Empty;

    public ObservableCollection<ConnectionProfile> Profiles { get; } = new();

    public MainWindowViewModel()
        : this(new MockClientService())
    {
    }

    public MainWindowViewModel(IClientService clientService)
    {
        this.clientService = clientService;
        AppendLog($"Backend: {clientService.BackendName}");
        LoadProfiles();
    }

    private void LoadProfiles()
    {
        Profiles.Clear();
        foreach (var profile in clientService.LoadProfiles())
        {
            Profiles.Add(profile);
        }

        SelectedProfile = Profiles.FirstOrDefault();
        LoadSelectedProfileIntoEditor();
    }

    partial void OnSelectedProfileChanged(ConnectionProfile? value)
    {
        LoadSelectedProfileIntoEditor();
    }

    private void LoadSelectedProfileIntoEditor()
    {
        ProfileName = SelectedProfile?.Name ?? string.Empty;
        ConnectionKey = SelectedProfile?.ConnectionKey ?? string.Empty;
        FullTunnel = SelectedProfile?.FullTunnel ?? true;
    }

    [RelayCommand(CanExecute = nameof(CanSaveProfile))]
    private void SaveProfile()
    {
        var profile = SelectedProfile ?? new ConnectionProfile();
        profile.Name = ProfileName.Trim();
        profile.ConnectionKey = ConnectionKey.Trim();
        profile.FullTunnel = FullTunnel;

        if (!Profiles.Contains(profile))
        {
            Profiles.Add(profile);
        }

        clientService.SaveProfiles(Profiles);
        SelectedProfile = profile;
        AppendLog($"Saved profile: {profile.Name}");
    }

    private bool CanSaveProfile()
    {
        return !string.IsNullOrWhiteSpace(ProfileName)
            && !string.IsNullOrWhiteSpace(ConnectionKey);
    }

    [RelayCommand]
    private void NewProfile()
    {
        SelectedProfile = null;
        ProfileName = string.Empty;
        ConnectionKey = string.Empty;
        FullTunnel = true;
        AppendLog("Ready for a new profile.");
    }

    [RelayCommand(CanExecute = nameof(HasSelectedProfile))]
    private void DeleteProfile()
    {
        if (SelectedProfile is null)
        {
            return;
        }

        var removed = SelectedProfile;
        Profiles.Remove(removed);
        clientService.SaveProfiles(Profiles);
        SelectedProfile = Profiles.FirstOrDefault();
        AppendLog($"Deleted profile: {removed.Name}");
    }

    [RelayCommand(CanExecute = nameof(CanConnect))]
    private async Task Connect()
    {
        if (SelectedProfile is null)
        {
            return;
        }

        try
        {
            var status = await clientService.ConnectAsync(SelectedProfile);
            ApplyStatus(status);
            AppendLog($"Connected to {SelectedProfile.DisplayEndpoint}");
        }
        catch (Exception ex)
        {
            ApplyError(ex);
        }
    }

    [RelayCommand(CanExecute = nameof(CanDisconnect))]
    private async Task Disconnect()
    {
        try
        {
            var status = await clientService.DisconnectAsync();
            ApplyStatus(status);
            AppendLog("Disconnected.");
        }
        catch (Exception ex)
        {
            ApplyError(ex);
        }
    }

    [RelayCommand]
    private async Task RefreshStatus()
    {
        try
        {
            ApplyStatus(await clientService.GetStatusAsync());
        }
        catch (Exception ex)
        {
            ApplyError(ex);
        }
    }

    private bool HasSelectedProfile()
    {
        return SelectedProfile is not null;
    }

    private bool CanConnect()
    {
        return SelectedProfile is not null && !IsConnected;
    }

    private bool CanDisconnect()
    {
        return IsConnected;
    }

    private void ApplyStatus(ConnectionStatus status)
    {
        IsConnected = status.IsConnected;
        StatusText = status.StatusText;
        BytesSent = status.BytesSent;
        BytesReceived = status.BytesReceived;
    }

    private void ApplyError(Exception ex)
    {
        IsConnected = false;
        StatusText = $"Error: {ex.Message}";
        AppendLog(StatusText);
    }

    private void AppendLog(string message)
    {
        LogText = $"{DateTimeOffset.Now:HH:mm:ss} {message}{Environment.NewLine}{LogText}";
    }
}
