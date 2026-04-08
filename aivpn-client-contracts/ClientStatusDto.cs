namespace Aivpn.Client.Contracts;

public sealed record ClientStatusDto
{
    public bool IsConnected { get; init; }

    public string StatusText { get; init; } = "Disconnected";

    public long BytesSent { get; init; }

    public long BytesReceived { get; init; }
}
