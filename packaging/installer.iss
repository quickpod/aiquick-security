; Inno Setup — AIQuick Security. Signed single-file installer, compiled in CI.
#define AppName "AIQuick Security"
#define AppVersion "1.0.5"

[Setup]
AppMutex=QuickOpen.AIQuickSecurity
AppId={{D82A9929-9823-4228-AABD-4EDEEE80D831}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=QuickOpen (quickopen.ai)
AppPublisherURL=https://quickopen.ai/projects/aiquick-security
DefaultDirName={autopf}\AIQuickSecurity
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\AIQuickSecurity.exe
; unins000.exe ships UNSIGNED by default, and on a machine with Smart App
; Control or a WDAC policy enforcing, Windows refuses to load it: the Uninstall
; button in Settings fails with CodeIntegrity 3077/3033 and WinError 4551,
; leaving the app impossible to remove through the normal route.
;
; Inno writes that binary on the USER'S machine at install time from a template
; baked into the installer, so no later signing hop can reach it - COMPILE time
; is the only moment it can be signed, which is what SignedUninstaller=yes does.
; That needs a SignTool where ISCC runs, so the ISCC step moved onto the signing
; machine (2026-08-21). ISCC signs uninst.e32, then the setup exe.
;
; Guarded by #ifdef so this same .iss still compiles anywhere without the token
; (CI, a laptop) - just unsigned. publish/scripts/compile-windows-installer.sh
; passes /DSIGNED_UNINSTALLER and defines the "quickopen" SignTool.
#ifdef SIGNED_UNINSTALLER
SignTool=quickopen
SignedUninstaller=yes
#endif
OutputDir=dist
OutputBaseFilename=AIQuickSecurity-Setup
SetupIconFile=..\aiquick-security.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardImageFile=branding\wizard-large.bmp
WizardSmallImageFile=branding\wizard-small.bmp
AppCopyright=Apache-2.0. 100%% AI-built, published on QuickOpen (quickopen.ai).
VersionInfoCompany=QuickOpen
VersionInfoProductName=AIQuick Security
VersionInfoVersion=1.0.4.0
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=AIQuick Security is a 100%% AI-built, open-source offline tool, published on QuickOpen (quickopen.ai).%n%nThis will install it on your computer.
BeveledLabel=QuickOpen · quickopen.ai

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "trustca"; Description: "Trust the QuickOpen Root CA (lets Windows verify QuickOpen signatures)"; GroupDescription: "Security:"; Flags: unchecked

[Files]
Source: "staging\AIQuickSecurity.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\quickopen-root.crt"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme skipifsourcedoesntexist
Source: "staging\LICENSE"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\AIQuick Security"; Filename: "{app}\AIQuickSecurity.exe"; IconFilename: "{app}\AIQuickSecurity.exe"
Name: "{group}\Uninstall AIQuick Security"; Filename: "{uninstallexe}"
Name: "{autodesktop}\AIQuick Security"; Filename: "{app}\AIQuickSecurity.exe"; IconFilename: "{app}\AIQuickSecurity.exe"; Tasks: desktopicon

[Run]
Filename: "certutil.exe"; Parameters: "-addstore -user Root ""{app}\quickopen-root.crt"""; Tasks: trustca; Flags: runhidden; StatusMsg: "Trusting the QuickOpen Root CA..."
Filename: "{app}\AIQuickSecurity.exe"; Description: "Launch AIQuick Security now"; Flags: nowait postinstall skipifsilent

; Full uninstall: remove every app-owned trace. The QuickOpen Root CA is
; intentionally NOT touched — it is shared by all QuickOpen apps.
[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\AIQuickSecurity"
