using System.Collections.Generic;

namespace Aivpn.Client.Contracts;

public sealed record ClientRequest
{
    public string Command { get; init; } = string.Empty;

    public ClientProfileDto? Profile { get; init; }

    public IReadOnlyList<ClientProfileDto>? Profiles { get; init; }
}
