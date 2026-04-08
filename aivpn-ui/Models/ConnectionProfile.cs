using System;

namespace Aivpn.Ui.Models;

public sealed class ConnectionProfile
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public string Name { get; set; } = "New connection";

    public string ConnectionKey { get; set; } = string.Empty;

    public bool FullTunnel { get; set; } = true;

    public string DisplayEndpoint
    {
        get
        {
            var endpoint = TryReadEndpoint(ConnectionKey);
            return string.IsNullOrWhiteSpace(endpoint) ? "No endpoint" : endpoint;
        }
    }

    private static string? TryReadEndpoint(string connectionKey)
    {
        var payload = connectionKey.Trim();
        if (payload.StartsWith("aivpn://", StringComparison.OrdinalIgnoreCase))
        {
            payload = payload["aivpn://".Length..];
        }

        if (string.IsNullOrWhiteSpace(payload))
        {
            return null;
        }

        try
        {
            var padded = payload.Replace('-', '+').Replace('_', '/');
            var padding = padded.Length % 4;
            if (padding > 0)
            {
                padded += new string('=', 4 - padding);
            }

            var bytes = Convert.FromBase64String(padded);
            using var doc = System.Text.Json.JsonDocument.Parse(bytes);
            return doc.RootElement.TryGetProperty("s", out var server)
                ? server.GetString()
                : null;
        }
        catch
        {
            return "Invalid key";
        }
    }
}
