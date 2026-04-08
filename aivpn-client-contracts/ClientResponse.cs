using System.Collections.Generic;

namespace Aivpn.Client.Contracts;

public sealed record ClientResponse
{
    public bool Ok { get; init; }

    public string? Error { get; init; }

    public IReadOnlyList<ClientProfileDto>? Profiles { get; init; }

    public ClientStatusDto? Status { get; init; }

    public static ClientResponse Success(
        IReadOnlyList<ClientProfileDto>? profiles = null,
        ClientStatusDto? status = null)
    {
        return new ClientResponse
        {
            Ok = true,
            Profiles = profiles,
            Status = status,
        };
    }

    public static ClientResponse Fail(string error)
    {
        return new ClientResponse
        {
            Ok = false,
            Error = error,
        };
    }
}
