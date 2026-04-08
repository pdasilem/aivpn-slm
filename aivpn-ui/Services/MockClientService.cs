using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Aivpn.Ui.Models;

namespace Aivpn.Ui.Services;

public sealed class MockClientService : IClientService
{
    private readonly List<ConnectionProfile> profiles = new();
    private ConnectionStatus status = new();

    public string BackendName => "mock";

    public MockClientService()
    {
        profiles.Add(new ConnectionProfile
        {
            Name = "Demo server",
            ConnectionKey = "aivpn://",
            FullTunnel = true,
        });
    }

    public IReadOnlyList<ConnectionProfile> LoadProfiles()
    {
        return profiles.ToList();
    }

    public void SaveProfiles(IEnumerable<ConnectionProfile> profiles)
    {
        this.profiles.Clear();
        this.profiles.AddRange(profiles);
    }

    public Task<ConnectionStatus> ConnectAsync(ConnectionProfile profile)
    {
        status = new ConnectionStatus
        {
            IsConnected = true,
            StatusText = $"Connected: {profile.Name}",
            BytesSent = 1024,
            BytesReceived = 4096,
        };
        return Task.FromResult(status);
    }

    public Task<ConnectionStatus> DisconnectAsync()
    {
        status = new ConnectionStatus
        {
            IsConnected = false,
            StatusText = "Disconnected",
            BytesSent = status.BytesSent,
            BytesReceived = status.BytesReceived,
        };
        return Task.FromResult(status);
    }

    public Task<ConnectionStatus> GetStatusAsync()
    {
        if (!status.IsConnected)
        {
            return Task.FromResult(status);
        }

        status = new ConnectionStatus
        {
            IsConnected = true,
            StatusText = status.StatusText,
            BytesSent = status.BytesSent + 2048,
            BytesReceived = status.BytesReceived + 8192,
        };
        return Task.FromResult(status);
    }
}
