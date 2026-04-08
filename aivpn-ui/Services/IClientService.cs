using System.Collections.Generic;
using System.Threading.Tasks;
using Aivpn.Ui.Models;

namespace Aivpn.Ui.Services;

public interface IClientService
{
    string BackendName { get; }

    IReadOnlyList<ConnectionProfile> LoadProfiles();

    void SaveProfiles(IEnumerable<ConnectionProfile> profiles);

    Task<ConnectionStatus> ConnectAsync(ConnectionProfile profile);

    Task<ConnectionStatus> DisconnectAsync();

    Task<ConnectionStatus> GetStatusAsync();
}
