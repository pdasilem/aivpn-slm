# Windows Client Helper Packaging

This directory contains the service install scripts for the Avalonia client architecture.

Expected install layout:

```text
C:\Program Files\AIVPN\Aivpn.Ui.exe
C:\Program Files\AIVPN\aivpn-clientd.exe
C:\Program Files\AIVPN\aivpn-client.exe
C:\Program Files\AIVPN\wintun.dll
```

Install the service from an elevated PowerShell:

```powershell
.\packaging\windows\install-clientd.ps1 -InstallDir "C:\Program Files\AIVPN"
```

Remove it:

```powershell
.\packaging\windows\uninstall-clientd.ps1
```

The Avalonia UI talks to this helper with:

```powershell
$env:AIVPN_UI_BACKEND = "pipe"
.\Aivpn.Ui.exe
```

The installer stage should call `install-clientd.ps1` after copying `Aivpn.Ui.exe`, `aivpn-clientd.exe`, `aivpn-client.exe`, and the signed `wintun.dll` into the install directory. Users should not manually place `wintun.dll` next to any exe.

Inno Setup skeleton:

```powershell
iscc /DSourceDir="C:\aivpn\publish\win-x64" /DOutputDir="C:\aivpn\dist" packaging\windows\aivpn-client-setup.iss
```

The source directory must contain the published Avalonia UI, `aivpn-clientd`, `aivpn-client.exe`, `wintun.dll`, `install-clientd.ps1`, and `uninstall-clientd.ps1`.
