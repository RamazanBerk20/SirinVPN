; Compile with NSIS >= 3.11. Install code is embedded, never taken from an
; untrusted existing installation or downloaded during installation.
!include "LogicLib.nsh"
!if ${NSIS_PACKEDVERSION} < 0x03011000
  !error "SirinVPN requires NSIS 3.11 or newer."
!endif
!define SIRINVPN_HELPER_SOURCE "${__FILEDIR__}/../../apps/desktop/src-tauri/binaries/windows/sirinvpn-windows-service.exe"

!macro SirinVPNInstallerHelper ARGUMENT
  ; Program Files is writable only by administrators. Create a fresh file there
  ; so an unelevated process cannot replace the elevated helper or its ancestors.
  ClearErrors
  GetTempFileName $R8 "$PROGRAMFILES64"
  ${If} ${Errors}
    SetErrorLevel 1
    Abort "Could not create a protected installation helper."
  ${EndIf}
  File /oname=$R8 "${SIRINVPN_HELPER_SOURCE}"
  ClearErrors
  StrCpy $R9 -1
  ExecWait '"$R8" ${ARGUMENT} "$INSTDIR"' $R9
  Delete "$R8"
  ${If} ${Errors}
  ${OrIf} $R9 != 0
    SetErrorLevel 1
    MessageBox MB_OK|MB_ICONSTOP "SirinVPN could not safely prepare its Windows service. Repair the installation and try again."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  ${If} $INSTDIR != "$PROGRAMFILES64\SirinVPN"
    SetErrorLevel 1
    MessageBox MB_OK|MB_ICONSTOP "Install SirinVPN in Program Files\SirinVPN so Windows can protect its VPN service."
    Abort
  ${EndIf}
  ; The installer performs no runtime download. WebView2 is an explicit Windows
  ; prerequisite, checked before stopping an existing VPN service.
  SetRegView 32
  ReadRegStr $R9 HKLM "SOFTWARE\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
  ${If} $R9 == ""
    ReadRegStr $R9 HKCU "SOFTWARE\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
  ${EndIf}
  SetRegView 64
  ${If} $R9 == ""
    SetErrorLevel 1
    MessageBox MB_OK|MB_ICONSTOP "Install the Microsoft Edge WebView2 Runtime from Microsoft, then run SirinVPN setup again."
    Abort
  ${EndIf}
  !insertmacro SirinVPNInstallerHelper "--prepare-install"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ClearErrors
  ExecWait '"$INSTDIR\sirinvpn-windows-service.exe" --install-service' $R9
  ${If} ${Errors}
  ${OrIf} $R9 != 0
    SetErrorLevel 1
    MessageBox MB_OK|MB_ICONSTOP "SirinVPN's service could not start. Run this installer again to repair it. Existing persistent protection has been retained."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode == 1
    !insertmacro SirinVPNInstallerHelper "--prepare-install"
  ${Else}
    ; The registered LocalSystem service clears only its own firewall, routes,
    ; adapter and encrypted session before SCM registration is removed.
    !insertmacro SirinVPNInstallerHelper "--uninstall-from"
  ${EndIf}
!macroend
