using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Aivpn.Client.Contracts;
using Aivpn.Ui.Models;

namespace Aivpn.Ui.Services;

public sealed class PipeClientService : IClientService
{
    private readonly string pipeName;
    private readonly JsonSerializerOptions jsonOptions = new(JsonSerializerDefaults.Web);

    public string BackendName => $"pipe:{pipeName}";

    public PipeClientService()
    {
        pipeName = Environment.GetEnvironmentVariable("AIVPN_CLIENTD_PIPE")
            ?? IpcDefaults.PipeName;
    }

    public IReadOnlyList<ConnectionProfile> LoadProfiles()
    {
        var response = SendAsync(new ClientRequest { Command = ClientCommands.ListProfiles }).GetAwaiter().GetResult();
        return (response.Profiles ?? Array.Empty<ClientProfileDto>()).Select(ToModel).ToList();
    }

    public void SaveProfiles(IEnumerable<ConnectionProfile> profiles)
    {
        SendAsync(new ClientRequest
        {
            Command = ClientCommands.SaveProfiles,
            Profiles = profiles.Select(ToDto).ToList(),
        }).GetAwaiter().GetResult();
    }

    public async Task<ConnectionStatus> ConnectAsync(ConnectionProfile profile)
    {
        var response = await SendAsync(new ClientRequest
        {
            Command = ClientCommands.Connect,
            Profile = ToDto(profile),
        });
        return ToModel(response.Status);
    }

    public async Task<ConnectionStatus> DisconnectAsync()
    {
        var response = await SendAsync(new ClientRequest { Command = ClientCommands.Disconnect });
        return ToModel(response.Status);
    }

    public async Task<ConnectionStatus> GetStatusAsync()
    {
        var response = await SendAsync(new ClientRequest { Command = ClientCommands.Status });
        return ToModel(response.Status);
    }

    private async Task<ClientResponse> SendAsync(ClientRequest request)
    {
        await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(3000);

        await using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };
        using var reader = new StreamReader(pipe, leaveOpen: true);

        await writer.WriteLineAsync(JsonSerializer.Serialize(request, jsonOptions));
        var line = await reader.ReadLineAsync();
        if (string.IsNullOrWhiteSpace(line))
        {
            throw new InvalidOperationException("Empty response from aivpn-clientd.");
        }

        var response = JsonSerializer.Deserialize<ClientResponse>(line, jsonOptions)
            ?? throw new InvalidOperationException("Malformed response from aivpn-clientd.");
        if (!response.Ok)
        {
            throw new InvalidOperationException(response.Error ?? "aivpn-clientd request failed.");
        }

        return response;
    }

    private static ClientProfileDto ToDto(ConnectionProfile profile)
    {
        return new ClientProfileDto
        {
            Id = profile.Id,
            Name = profile.Name,
            ConnectionKey = profile.ConnectionKey,
            FullTunnel = profile.FullTunnel,
        };
    }

    private static ConnectionProfile ToModel(ClientProfileDto profile)
    {
        return new ConnectionProfile
        {
            Id = string.IsNullOrWhiteSpace(profile.Id) ? Guid.NewGuid().ToString("N") : profile.Id,
            Name = profile.Name,
            ConnectionKey = profile.ConnectionKey,
            FullTunnel = profile.FullTunnel,
        };
    }

    private static ConnectionStatus ToModel(ClientStatusDto? status)
    {
        return new ConnectionStatus
        {
            IsConnected = status?.IsConnected ?? false,
            StatusText = status?.StatusText ?? "Disconnected",
            BytesSent = status?.BytesSent ?? 0,
            BytesReceived = status?.BytesReceived ?? 0,
        };
    }
}
