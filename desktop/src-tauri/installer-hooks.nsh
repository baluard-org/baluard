; Native-messaging registration for the browser bridge. The registry
; default values point at the manifest JSONs the daemon writes beside
; itself on first startup (baluard-core nmh_register), so nothing here
; needs backslash escaping and app updates re-point the path themselves.
; Between install and the first app launch the manifest files do not
; exist yet; the extension needs the running app anyway. Two host names:
; 0.1.0 store extensions pair through the legacy name, 0.1.3+ through
; the canonical one. Firefox reads the same keys under Software\Mozilla.
!macro NSIS_HOOK_POSTINSTALL
  WriteRegStr HKCU "Software\Google\Chrome\NativeMessagingHosts\app.baluard.browser" "" "$INSTDIR\app.baluard.browser.json"
  WriteRegStr HKCU "Software\Google\Chrome\NativeMessagingHosts\xyz.actitud.baluard" "" "$INSTDIR\xyz.actitud.baluard.json"
  WriteRegStr HKCU "Software\Chromium\NativeMessagingHosts\app.baluard.browser" "" "$INSTDIR\app.baluard.browser.json"
  WriteRegStr HKCU "Software\Chromium\NativeMessagingHosts\xyz.actitud.baluard" "" "$INSTDIR\xyz.actitud.baluard.json"
  WriteRegStr HKCU "Software\Microsoft\Edge\NativeMessagingHosts\app.baluard.browser" "" "$INSTDIR\app.baluard.browser.json"
  WriteRegStr HKCU "Software\Microsoft\Edge\NativeMessagingHosts\xyz.actitud.baluard" "" "$INSTDIR\xyz.actitud.baluard.json"
  WriteRegStr HKCU "Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\app.baluard.browser" "" "$INSTDIR\app.baluard.browser.json"
  WriteRegStr HKCU "Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\xyz.actitud.baluard" "" "$INSTDIR\xyz.actitud.baluard.json"
  WriteRegStr HKCU "Software\Vivaldi\NativeMessagingHosts\app.baluard.browser" "" "$INSTDIR\app.baluard.browser.json"
  WriteRegStr HKCU "Software\Vivaldi\NativeMessagingHosts\xyz.actitud.baluard" "" "$INSTDIR\xyz.actitud.baluard.json"
  WriteRegStr HKCU "Software\Mozilla\NativeMessagingHosts\app.baluard.browser" "" "$INSTDIR\app.baluard.browser.firefox.json"
  WriteRegStr HKCU "Software\Mozilla\NativeMessagingHosts\xyz.actitud.baluard" "" "$INSTDIR\xyz.actitud.baluard.firefox.json"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\app.baluard.browser"
  DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\xyz.actitud.baluard"
  DeleteRegKey HKCU "Software\Chromium\NativeMessagingHosts\app.baluard.browser"
  DeleteRegKey HKCU "Software\Chromium\NativeMessagingHosts\xyz.actitud.baluard"
  DeleteRegKey HKCU "Software\Microsoft\Edge\NativeMessagingHosts\app.baluard.browser"
  DeleteRegKey HKCU "Software\Microsoft\Edge\NativeMessagingHosts\xyz.actitud.baluard"
  DeleteRegKey HKCU "Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\app.baluard.browser"
  DeleteRegKey HKCU "Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\xyz.actitud.baluard"
  DeleteRegKey HKCU "Software\Vivaldi\NativeMessagingHosts\app.baluard.browser"
  DeleteRegKey HKCU "Software\Vivaldi\NativeMessagingHosts\xyz.actitud.baluard"
  DeleteRegKey HKCU "Software\Mozilla\NativeMessagingHosts\app.baluard.browser"
  DeleteRegKey HKCU "Software\Mozilla\NativeMessagingHosts\xyz.actitud.baluard"
  ; The daemon-written manifests die with $INSTDIR; delete them so the
  ; uninstaller's RMDir does not fail on a non-empty folder.
  Delete "$INSTDIR\app.baluard.browser.json"
  Delete "$INSTDIR\xyz.actitud.baluard.json"
  Delete "$INSTDIR\app.baluard.browser.firefox.json"
  Delete "$INSTDIR\xyz.actitud.baluard.firefox.json"
!macroend
