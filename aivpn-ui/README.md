# AIVPN Avalonia UI

Avalonia 12 client UI for Windows and Linux desktop. The same UI shell is intended to be reused for the jailbreak iOS target if the runtime constraints allow it.

## Backends

The UI chooses its backend through `AIVPN_UI_BACKEND`:

- unset or `mock`: in-memory backend for UI development without admin/root privileges.
- `process`: stores profiles in JSON and starts `aivpn-client` directly.
- `pipe`: talks to `aivpn-clientd` over the shared IPC contract.

Useful environment variables:

- `AIVPN_CLIENT_PATH`: path to `aivpn-client` or `aivpn-client.exe`.
- `AIVPN_UI_CONFIG_DIR`: profile storage directory for the `process` backend.
- `AIVPN_CLIENTD_PIPE`: named pipe used by the `pipe` backend.

## Local Checks

```bash
dotnet build aivpn-ui/Aivpn.Ui.csproj
dotnet build aivpn-clientd/Aivpn.Clientd.csproj
```

Smoke check for the daemon contract without a GUI:

```bash
printf '%s\n' '{"command":"listProfiles"}' \
  | AIVPN_CLIENTD_CONFIG_DIR=/tmp/aivpn-clientd-smoke \
    dotnet run --project aivpn-clientd/Aivpn.Clientd.csproj -- --stdio-once
```

Run the UI in pipe mode after starting `aivpn-clientd`:

```bash
dotnet run --project aivpn-clientd/Aivpn.Clientd.csproj
AIVPN_UI_BACKEND=pipe dotnet run --project aivpn-ui/Aivpn.Ui.csproj
```
