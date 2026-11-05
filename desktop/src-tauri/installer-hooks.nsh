; Native-messaging registration for the browser bridge. The registry
; default values point at the manifest JSONs the daemon writes beside
; itself on first startup (baluard-core nmh_register), so nothing here
; needs backslash escaping and app updates re-point the path themselves.
; Two host names: 0.1.0 store extensions pair through the legacy name,
; 0.1.1+ through the canonical one.
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
!macroend
