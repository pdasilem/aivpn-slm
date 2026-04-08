namespace Aivpn.Ui.Models;

public sealed class ConnectionStatus
{
    public bool IsConnected { get; init; }

    public string StatusText { get; init; } = "Disconnected";

    public long BytesSent { get; init; }

    public long BytesReceived { get; init; }
}
