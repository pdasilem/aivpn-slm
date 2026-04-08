# AIVPN Client Daemon

`aivpn-clientd` is the first service/helper layer for the Avalonia client UI. It exposes a small JSON IPC contract over .NET named pipes and manages profile persistence plus the `aivpn-client` process.

The executable is built on .NET Generic Host and can run as a console app, systemd service, or Windows Service:

- Windows: install it as an elevated Windows Service and package it with `aivpn-client.exe` and `wintun.dll`.
- Linux: run it as a systemd service, then add polkit/system integration in a later hardening step.
- iOS jailbreak: reuse the same command/status contract if Avalonia or another UI shell talks to a local daemon.

Environment variables:

- `AIVPN_CLIENT_PATH`: path to the tunnel client binary.
- `AIVPN_CLIENTD_CONFIG_DIR`: profile storage directory.
- `AIVPN_CLIENTD_PIPE`: named pipe name, default `aivpn-clientd`.

The `--stdio-once` mode handles one JSON request from stdin and writes one JSON response to stdout. It exists for smoke tests and CI.

Packaging skeletons:

- `packaging/windows/install-clientd.ps1`
- `packaging/windows/uninstall-clientd.ps1`
- `packaging/linux/aivpn-clientd.service`
