using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Aivpn.Ui.Models;

namespace Aivpn.Ui.Services;

public sealed class ProcessClientService : IClientService, IDisposable
{
    private readonly string profilePath;
    private readonly string clientPath;
    private readonly JsonSerializerOptions jsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private Process? clientProcess;
    private ConnectionProfile? activeProfile;
    private long lastBytesSent;
    private long lastBytesReceived;

    public string BackendName => "process";

    public ProcessClientService()
    {
        profilePath = Path.Combine(GetConfigDirectory(), "profiles.json");
        clientPath = ResolveClientPath();
    }

    public IReadOnlyList<ConnectionProfile> LoadProfiles()
    {
        if (!File.Exists(profilePath))
        {
            return Array.Empty<ConnectionProfile>();
        }

        using var stream = File.OpenRead(profilePath);
        return JsonSerializer.Deserialize<List<ConnectionProfile>>(stream, jsonOptions)
            ?? new List<ConnectionProfile>();
    }

    public void SaveProfiles(IEnumerable<ConnectionProfile> profiles)
    {
        var directory = Path.GetDirectoryName(profilePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        using var stream = File.Create(profilePath);
        JsonSerializer.Serialize(stream, profiles.ToList(), jsonOptions);
    }

    public Task<ConnectionStatus> ConnectAsync(ConnectionProfile profile)
    {
        if (IsProcessRunning())
        {
            return Task.FromResult(BuildConnectedStatus($"Connected: {activeProfile?.Name ?? profile.Name}"));
        }

        if (string.IsNullOrWhiteSpace(profile.ConnectionKey))
        {
            throw new InvalidOperationException("Connection key is empty.");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = clientPath,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("--connection-key");
        startInfo.ArgumentList.Add(profile.ConnectionKey);
        if (profile.FullTunnel)
        {
            startInfo.ArgumentList.Add("--full-tunnel");
        }

        clientProcess = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Failed to start {clientPath}.");
        activeProfile = profile;

        return Task.FromResult(BuildConnectedStatus($"Connecting: {profile.Name}"));
    }

    public Task<ConnectionStatus> DisconnectAsync()
    {
        if (IsProcessRunning())
        {
            clientProcess?.Kill(entireProcessTree: true);
            clientProcess?.WaitForExit(5000);
        }

        clientProcess?.Dispose();
        clientProcess = null;
        activeProfile = null;

        return Task.FromResult(new ConnectionStatus
        {
            IsConnected = false,
            StatusText = "Disconnected",
            BytesSent = lastBytesSent,
            BytesReceived = lastBytesReceived,
        });
    }

    public Task<ConnectionStatus> GetStatusAsync()
    {
        if (!IsProcessRunning())
        {
            clientProcess?.Dispose();
            clientProcess = null;
            activeProfile = null;
            return Task.FromResult(new ConnectionStatus
            {
                IsConnected = false,
                StatusText = "Disconnected",
                BytesSent = lastBytesSent,
                BytesReceived = lastBytesReceived,
            });
        }

        return Task.FromResult(BuildConnectedStatus($"Connected: {activeProfile?.Name ?? "AIVPN"}"));
    }

    public void Dispose()
    {
        clientProcess?.Dispose();
    }

    private ConnectionStatus BuildConnectedStatus(string statusText)
    {
        ReadTrafficStats();
        return new ConnectionStatus
        {
            IsConnected = true,
            StatusText = statusText,
            BytesSent = lastBytesSent,
            BytesReceived = lastBytesReceived,
        };
    }

    private bool IsProcessRunning()
    {
        return clientProcess is { HasExited: false };
    }

    private void ReadTrafficStats()
    {
        foreach (var path in new[] { "/var/run/aivpn/traffic.stats", "/tmp/aivpn-traffic.stats" })
        {
            if (!File.Exists(path))
            {
                continue;
            }

            var text = File.ReadAllText(path);
            foreach (var part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var pieces = part.Split(':', 2, StringSplitOptions.TrimEntries);
                if (pieces.Length != 2 || !long.TryParse(pieces[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
                {
                    continue;
                }

                if (string.Equals(pieces[0], "sent", StringComparison.OrdinalIgnoreCase))
                {
                    lastBytesSent = value;
                }
                else if (string.Equals(pieces[0], "received", StringComparison.OrdinalIgnoreCase))
                {
                    lastBytesReceived = value;
                }
            }

            return;
        }
    }

    private static string ResolveClientPath()
    {
        var fromEnv = Environment.GetEnvironmentVariable("AIVPN_CLIENT_PATH");
        if (!string.IsNullOrWhiteSpace(fromEnv))
        {
            return fromEnv;
        }

        var executableName = OperatingSystem.IsWindows() ? "aivpn-client.exe" : "aivpn-client";
        var bundledPath = Path.Combine(AppContext.BaseDirectory, executableName);
        return File.Exists(bundledPath) ? bundledPath : executableName;
    }

    private static string GetConfigDirectory()
    {
        var fromEnv = Environment.GetEnvironmentVariable("AIVPN_UI_CONFIG_DIR");
        if (!string.IsNullOrWhiteSpace(fromEnv))
        {
            return fromEnv;
        }

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (!string.IsNullOrWhiteSpace(appData))
        {
            return Path.Combine(appData, "AIVPN");
        }

        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return string.IsNullOrWhiteSpace(home)
            ? Path.Combine(Path.GetTempPath(), "AIVPN")
            : Path.Combine(home, ".config", "aivpn");
    }
}
