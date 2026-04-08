using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Text.Json;
using Aivpn.Client.Contracts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

var pipeName = ReadOption(args, "--pipe")
    ?? Environment.GetEnvironmentVariable("AIVPN_CLIENTD_PIPE")
    ?? IpcDefaults.PipeName;

var daemon = new ClientDaemon();
if (args.Any(arg => string.Equals(arg, "--stdio-once", StringComparison.OrdinalIgnoreCase)))
{
    await daemon.HandleAsync(Console.OpenStandardInput(), Console.OpenStandardOutput(), CancellationToken.None);
    return;
}

await Host.CreateDefaultBuilder(args)
    .UseSystemd()
    .UseWindowsService(options =>
    {
        options.ServiceName = "AIVPN Client Daemon";
    })
    .ConfigureServices(services =>
    {
        services.AddSingleton(daemon);
        services.AddSingleton(new DaemonOptions(pipeName));
        services.AddHostedService<ClientDaemonWorker>();
    })
    .Build()
    .RunAsync();

static string? ReadOption(string[] args, string name)
{
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
        {
            return args[i + 1];
        }
    }

    return null;
}

internal sealed record DaemonOptions(string PipeName);

internal sealed class ClientDaemonWorker : BackgroundService
{
    private readonly ClientDaemon daemon;
    private readonly DaemonOptions options;
    private readonly ILogger<ClientDaemonWorker> logger;

    public ClientDaemonWorker(
        ClientDaemon daemon,
        DaemonOptions options,
        ILogger<ClientDaemonWorker> logger)
    {
        this.daemon = daemon;
        this.options = options;
        this.logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("AIVPN client daemon listening on pipe {PipeName}", options.PipeName);

        while (!stoppingToken.IsCancellationRequested)
        {
            var pipe = new NamedPipeServerStream(
                options.PipeName,
                PipeDirection.InOut,
                NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            try
            {
                await pipe.WaitForConnectionAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                await pipe.DisposeAsync();
                break;
            }

            _ = Task.Run(async () =>
            {
                await using (pipe)
                {
                    await daemon.HandleAsync(pipe, pipe, stoppingToken);
                }
            }, CancellationToken.None);
        }
    }
}

internal sealed class ClientDaemon
{
    private readonly string profilePath;
    private readonly string clientPath;
    private readonly JsonSerializerOptions jsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private Process? clientProcess;
    private ClientProfileDto? activeProfile;
    private long lastBytesSent;
    private long lastBytesReceived;

    public ClientDaemon()
    {
        profilePath = Path.Combine(GetConfigDirectory(), "profiles.json");
        clientPath = ResolveClientPath();
    }

    public async Task HandleAsync(Stream input, Stream output, CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(input, leaveOpen: true);
        await using var writer = new StreamWriter(output, leaveOpen: true) { AutoFlush = true };

        var requestJson = await reader.ReadLineAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(requestJson))
        {
            await WriteResponseAsync(writer, ClientResponse.Fail("Empty request."), cancellationToken);
            return;
        }

        try
        {
            var request = JsonSerializer.Deserialize<ClientRequest>(requestJson, jsonOptions)
                ?? new ClientRequest();
            await WriteResponseAsync(writer, HandleRequest(request), cancellationToken);
        }
        catch (Exception ex)
        {
            await WriteResponseAsync(writer, ClientResponse.Fail(ex.Message), cancellationToken);
        }
    }

    private ClientResponse HandleRequest(ClientRequest request)
    {
        return request.Command switch
        {
            ClientCommands.ListProfiles => ClientResponse.Success(profiles: LoadProfiles()),
            ClientCommands.SaveProfiles => SaveProfiles(request.Profiles ?? Array.Empty<ClientProfileDto>()),
            ClientCommands.Connect => Connect(request.Profile ?? throw new InvalidOperationException("Missing profile.")),
            ClientCommands.Disconnect => Disconnect(),
            ClientCommands.Status => ClientResponse.Success(status: GetStatus()),
            _ => ClientResponse.Fail($"Unknown command: {request.Command}"),
        };
    }

    private IReadOnlyList<ClientProfileDto> LoadProfiles()
    {
        if (!File.Exists(profilePath))
        {
            return Array.Empty<ClientProfileDto>();
        }

        using var stream = File.OpenRead(profilePath);
        return JsonSerializer.Deserialize<List<ClientProfileDto>>(stream, jsonOptions)
            ?? new List<ClientProfileDto>();
    }

    private ClientResponse SaveProfiles(IEnumerable<ClientProfileDto> profiles)
    {
        var savedProfiles = profiles.ToList();
        var directory = Path.GetDirectoryName(profilePath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        using var stream = File.Create(profilePath);
        JsonSerializer.Serialize(stream, savedProfiles, jsonOptions);
        return ClientResponse.Success(profiles: savedProfiles);
    }

    private ClientResponse Connect(ClientProfileDto profile)
    {
        if (IsProcessRunning())
        {
            return ClientResponse.Success(status: GetStatus());
        }

        if (string.IsNullOrWhiteSpace(profile.ConnectionKey))
        {
            return ClientResponse.Fail("Connection key is empty.");
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

        return ClientResponse.Success(status: BuildConnectedStatus($"Connecting: {profile.Name}"));
    }

    private ClientResponse Disconnect()
    {
        if (IsProcessRunning())
        {
            clientProcess?.Kill(entireProcessTree: true);
            clientProcess?.WaitForExit(5000);
        }

        clientProcess?.Dispose();
        clientProcess = null;
        activeProfile = null;

        return ClientResponse.Success(status: BuildDisconnectedStatus());
    }

    private ClientStatusDto GetStatus()
    {
        if (!IsProcessRunning())
        {
            clientProcess?.Dispose();
            clientProcess = null;
            activeProfile = null;
            return BuildDisconnectedStatus();
        }

        return BuildConnectedStatus($"Connected: {activeProfile?.Name ?? "AIVPN"}");
    }

    private ClientStatusDto BuildConnectedStatus(string statusText)
    {
        ReadTrafficStats();
        return new ClientStatusDto
        {
            IsConnected = true,
            StatusText = statusText,
            BytesSent = lastBytesSent,
            BytesReceived = lastBytesReceived,
        };
    }

    private ClientStatusDto BuildDisconnectedStatus()
    {
        return new ClientStatusDto
        {
            IsConnected = false,
            StatusText = "Disconnected",
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

    private static Task WriteResponseAsync(
        StreamWriter writer,
        ClientResponse response,
        CancellationToken cancellationToken)
    {
        return writer.WriteLineAsync(
            JsonSerializer.Serialize(response, new JsonSerializerOptions(JsonSerializerDefaults.Web)).AsMemory(),
            cancellationToken);
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
        var fromEnv = Environment.GetEnvironmentVariable("AIVPN_CLIENTD_CONFIG_DIR");
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
