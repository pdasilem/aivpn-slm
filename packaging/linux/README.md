# Linux Client Helper Packaging

This directory contains the first systemd packaging skeleton for `aivpn-clientd`.

Expected install layout:

```text
/opt/aivpn/aivpn-ui
/opt/aivpn/aivpn-clientd
/opt/aivpn/aivpn-client
/etc/systemd/system/aivpn-clientd.service
/etc/aivpn/client/profiles.json
```

Install check:

```bash
sudo install -d /opt/aivpn /etc/aivpn/client
sudo install -m 0755 aivpn-clientd /opt/aivpn/aivpn-clientd
sudo install -m 0755 aivpn-client /opt/aivpn/aivpn-client
sudo install -m 0644 packaging/linux/aivpn-clientd.service /etc/systemd/system/aivpn-clientd.service
sudo systemctl daemon-reload
sudo systemctl enable --now aivpn-clientd
systemctl status aivpn-clientd
```

Run the Avalonia UI against the helper:

```bash
AIVPN_UI_BACKEND=pipe dotnet run --project aivpn-ui/Aivpn.Ui.csproj
```

This is intentionally still a privileged root service. A later packaging stage should narrow this with polkit or a smaller platform helper responsible only for TUN/routes.
