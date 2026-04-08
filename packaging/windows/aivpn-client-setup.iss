#define MyAppName "AIVPN"
#define MyAppVersion "0.3.0"
#define MyAppPublisher "AIVPN Team"

#ifndef SourceDir
  #define SourceDir "."
#endif

#ifndef OutputDir
  #define OutputDir "."
#endif

#ifndef IconFile
  #define IconFile AddBackslash(SourceDir) + "aivpn.ico"
#endif

#if FileExists(IconFile)
  #define HasInstallerIcon
#endif

#ifndef SignToolCommand
  #define SignToolCommand ""
#endif

#if SignToolCommand != ""
  #define HasSignTool
#endif

[Setup]
AppId={{49B99497-B39C-4F49-BC2B-A6F58DE4DCA6}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\AIVPN
DefaultGroupName=AIVPN
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
OutputDir={#OutputDir}
OutputBaseFilename=aivpn-client-setup
UninstallDisplayIcon={app}\Aivpn.Ui.exe
#ifdef HasInstallerIcon
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\aivpn.ico
#endif
#ifdef HasSignTool
SignTool=aivpn_sign
SignedUninstaller=yes
#endif

#ifdef HasSignTool
[SignTools]
Name: "aivpn_sign"; Command: "{#SignToolCommand}"
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#SourceDir}\Aivpn.Ui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\Aivpn.Ui.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\Aivpn.Client.Contracts.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\aivpn-clientd.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\aivpn-clientd.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\aivpn-client.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\*.dll"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs
Source: "{#SourceDir}\*.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\install-clientd.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\uninstall-clientd.ps1"; DestDir: "{app}"; Flags: ignoreversion
#ifdef HasInstallerIcon
Source: "{#IconFile}"; DestDir: "{app}"; DestName: "aivpn.ico"; Flags: ignoreversion
#endif

[Icons]
#ifdef HasInstallerIcon
Name: "{autoprograms}\AIVPN"; Filename: "{app}\Aivpn.Ui.exe"; WorkingDir: "{app}"; IconFilename: "{app}\aivpn.ico"
Name: "{autodesktop}\AIVPN"; Filename: "{app}\Aivpn.Ui.exe"; WorkingDir: "{app}"; IconFilename: "{app}\aivpn.ico"
#else
Name: "{autoprograms}\AIVPN"; Filename: "{app}\Aivpn.Ui.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\AIVPN"; Filename: "{app}\Aivpn.Ui.exe"; WorkingDir: "{app}"
#endif
Name: "{autoprograms}\Uninstall AIVPN"; Filename: "{uninstallexe}"

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\install-clientd.ps1"" -InstallDir ""{app}"""; Flags: runhidden waituntilterminated
Filename: "{app}\Aivpn.Ui.exe"; Description: "Launch AIVPN"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\uninstall-clientd.ps1"""; Flags: runhidden waituntilterminated
