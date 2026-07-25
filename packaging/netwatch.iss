; Inno Setup script for the netwatch Windows installer.
;
; Produces netwatch-setup-<version>.exe: a real installer with a Start Menu
; entry, an uninstaller, and version metadata Windows can see -- rather than a
; loose ConnectionViewer.exe with no way to tell what it is or remove it.
;
; Build (CI does this automatically on a version tag):
;   iscc /DAppVersion=1.0.0 packaging\netwatch.iss
;
; Expects dist\ConnectionViewer.exe to already be built by PyInstaller.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

#define AppName "netwatch"
#define AppExeName "ConnectionViewer.exe"
#define AppPublisher "Tombo192"
#define AppURL "https://github.com/t0mbo192/netwatch"

[Setup]
; Fixed AppId: lets a new version upgrade in place instead of installing
; alongside the old one. Never change it.
AppId={{8F3A1C42-9B7E-4D5A-A1F3-2C6E8B4D9017}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
VersionInfoVersion={#AppVersion}

; Per-user install, so no admin prompt (UAC) is needed.
PrivilegesRequired=lowest
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
AllowNoIcons=yes

OutputDir=..\dist
OutputBaseFilename=netwatch-setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible

; Refuse to downgrade over a newer install.
AppMutex=netwatch-single-instance

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; \
  GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";          DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE";            DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}";            Filename: "{app}\{#AppExeName}"
Name: "{group}\Capture drop folder";   Filename: "{userdocs}\Captures"
Name: "{group}\Uninstall {#AppName}";  Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}";      Filename: "{app}\{#AppExeName}"; \
  Tasks: desktopicon

[Dirs]
; The folder netwatch scans for the newest capture when opened with no file.
Name: "{userdocs}\Captures"

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch {#AppName}"; \
  Flags: nowait postinstall skipifsilent

[Code]
function WiresharkPresent: Boolean;
begin
  { netwatch reads captures with Wireshark's tshark, so flag a missing install
    up front rather than letting the app fail on first use. }
  Result := FileExists(ExpandConstant('{commonpf}\Wireshark\tshark.exe')) or
            FileExists(ExpandConstant('{commonpf32}\Wireshark\tshark.exe'));
end;

function InitializeSetup: Boolean;
begin
  Result := True;
  if not WiresharkPresent then
  begin
    if MsgBox('Wireshark was not found on this computer.' + #13#10#13#10 +
              'netwatch reads capture files using tshark, which ships with '  +
              'Wireshark, so it will not be able to open a capture until '    +
              'Wireshark is installed from https://www.wireshark.org.'        +
              #13#10#13#10 + 'Continue with the installation anyway?',
              mbConfirmation, MB_YESNO) = IDNO then
      Result := False;
  end;
end;
