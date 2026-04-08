param(
    [string]$InstallDir = "$env:ProgramFiles\AIVPN",
    [string]$ServiceName = "AIVPNClientD",
    [string]$PipeName = "aivpn-clientd"
)

$ErrorActionPreference = "Stop"

function Ensure-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return
    }

    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $PSCommandPath),
        "-InstallDir", ('"{0}"' -f $InstallDir),
        "-ServiceName", ('"{0}"' -f $ServiceName),
        "-PipeName", ('"{0}"' -f $PipeName)
    )
    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs | Out-Null
    exit 0
}

Ensure-Admin

$clientd = Join-Path $InstallDir "aivpn-clientd.exe"
$client = Join-Path $InstallDir "aivpn-client.exe"
$wintun = Join-Path $InstallDir "wintun.dll"

if (-not (Test-Path $clientd)) {
    throw "Missing $clientd"
}
if (-not (Test-Path $client)) {
    throw "Missing $client"
}
if (-not (Test-Path $wintun)) {
    throw "Missing $wintun"
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name $ServiceName -Force
    }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

$binaryPath = '"{0}" --pipe "{1}"' -f $clientd, $PipeName
New-Service `
    -Name $ServiceName `
    -BinaryPathName $binaryPath `
    -DisplayName "AIVPN Client Daemon" `
    -Description "Privileged AIVPN helper for tunnel process control" `
    -StartupType Automatic | Out-Null

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name "Environment" -Value @(
    "AIVPN_CLIENT_PATH=$client",
    "AIVPN_CLIENTD_CONFIG_DIR=$env:ProgramData\AIVPN",
    "AIVPN_CLIENTD_PIPE=$PipeName"
)

Start-Service -Name $ServiceName
Get-Service -Name $ServiceName
