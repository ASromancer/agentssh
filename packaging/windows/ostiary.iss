#ifndef Version
  #define Version "0.0.0"
#endif
#ifndef SrcDir
  #define SrcDir "."
#endif
#ifndef OutDir
  #define OutDir "."
#endif

[Setup]
AppId={{6C0B7E1A-3F2D-4E7B-9A51-0D2F7C9E4B10}
AppName=Ostiary
AppVersion={#Version}
AppPublisher=ASromancer
AppPublisherURL=https://github.com/ASromancer/ostiary
DefaultDirName={userpf}\Ostiary
DefaultGroupName=Ostiary
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutDir}
OutputBaseFilename=Ostiary-Setup-{#Version}-x64
SetupIconFile={#SrcDir}\ostiary.ico
UninstallDisplayIcon={app}\ostiary.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
CloseApplications=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked
Name: "autostart"; Description: "Start Ostiary when I sign in"

[Files]
Source: "{#SrcDir}\ostiary.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\ostiary-app.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\ostiary.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\Ostiary"; Filename: "{app}\ostiary-app.exe"; IconFilename: "{app}\ostiary.ico"
Name: "{userdesktop}\Ostiary"; Filename: "{app}\ostiary-app.exe"; IconFilename: "{app}\ostiary.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\ostiary.exe"; Parameters: "install-service --yes"; Flags: runhidden; Tasks: autostart
Filename: "{app}\ostiary-app.exe"; Description: "Open Ostiary"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "{app}\ostiary.exe"; Parameters: "stop"; Flags: runhidden; RunOnceId: "stop"
Filename: "{app}\ostiary.exe"; Parameters: "uninstall-service --yes"; Flags: runhidden; RunOnceId: "unsvc"

[Code]
function NeedsAddPath(Dir: string): Boolean;
var
  Paths: string;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Paths) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') = 0;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  { An upgrade over a running daemon: stop it so its files can be replaced. }
  if FileExists(ExpandConstant('{app}\ostiary.exe')) then
    Exec(ExpandConstant('{app}\ostiary.exe'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;
