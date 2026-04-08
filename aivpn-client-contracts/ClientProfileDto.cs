namespace Aivpn.Client.Contracts;

public sealed record ClientProfileDto
{
    public string Id { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string ConnectionKey { get; init; } = string.Empty;

    public bool FullTunnel { get; init; } = true;
}
