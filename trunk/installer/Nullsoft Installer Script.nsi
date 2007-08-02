; Sulley Fuzzing Framework Installer
; Aaron Portnoy
; TippingPoint Security Research Team
; (c) 2007

; HM NIS Edit Wizard helper defines
!define PRODUCT_NAME "Sulley Fuzzing Framework"
!define PRODUCT_VERSION "1.0"
!define PRODUCT_PUBLISHER "Pedram Amini and Aaron Portnoy"
!define PRODUCT_WEB_SITE "http://www.fuzzing.org"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\Sulley.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; MUI 1.67 compatible ------
!include "MUI.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "..\..\sulley_icon.ico"
!define MUI_UNICON "..\..\sulley_icon.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; License page
; !insertmacro MUI_PAGE_LICENSE "" "$PROGRAMFILES\Sulley Fuzzing Framework\LICENSE.txt"
; Directory page
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION "LaunchDocsAndShell"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

; MUI end ------


Function LaunchDocsAndShell
   ExecShell "" "$PROGRAMFILES\Sulley Fuzzing Framework\docs\index.html"
   Exec 'cmd.exe /c cd "$PROGRAMFILES\Sulley Fuzzing Framework"'
   Exec 'cmd.exe /c cd "$PROGRAMFILES\Sulley Fuzzing Framework"'
FunctionEnd

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "Sulley Fuzzing Framework.exe"
InstallDir "$PROGRAMFILES\Sulley Fuzzing Framework"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
ShowInstDetails show
ShowUnInstDetails show

Section "Sulley" SEC01
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework"
  SetOverwrite try
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\docs"
  File "..\docs\generate_epydocs.bat"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\docs\img"
  File "..\docs\img\crash_paths.gif"
  File "..\docs\img\pcap.gif"
  File "..\docs\img\session_test.gif"
  File "..\docs\img\sulley.jpg"
  File "..\docs\img\sulley_web_interface.gif"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\docs"
  File "..\docs\index.html"
  File "..\docs\stylesheet.css"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework"
  File "..\LICENSE.txt"
  File "..\network_monitor.py"
  File "..\process_monitor.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\requests"
  File "..\requests\http.py"
  File "..\requests\jabber.py"
  File "..\requests\ldap.py"
  File "..\requests\ndmp.py"
  File "..\requests\rendezvous.py"
  File "..\requests\stun.py"
  File "..\requests\trend.py"
  File "..\requests\xbox.py"
  File "..\requests\__init__.py"
  File "..\requests\___REQUESTS___.html"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\sulley"
  File "..\sulley\blocks.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\sulley\legos"
  File "..\sulley\legos\ber.py"
  File "..\sulley\legos\dcerpc.py"
  File "..\sulley\legos\misc.py"
  File "..\sulley\legos\xdr.py"
  File "..\sulley\legos\__init__.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\sulley"
  File "..\sulley\pedrpc.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\sulley\pgraph"
  File "..\sulley\pgraph\cluster.py"
  File "..\sulley\pgraph\edge.py"
  File "..\sulley\pgraph\graph.py"
  File "..\sulley\pgraph\node.py"
  File "..\sulley\pgraph\__init__.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\sulley"
  File "..\sulley\primitives.py"
  File "..\sulley\sessions.py"
  File "..\sulley\sex.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\sulley\utils"
  File "..\sulley\utils\dcerpc.py"
  File "..\sulley\utils\misc.py"
  File "..\sulley\utils\scada.py"
  File "..\sulley\utils\__init__.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\sulley"
  File "..\sulley\__init__.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework"
  File "..\unit_test.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\unit_tests"
  File "..\unit_tests\blocks.py"
  File "..\unit_tests\legos.py"
  File "..\unit_tests\primitives.py"
  File "..\unit_tests\__init__.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\utils"
  File "..\utils\crashbin_explorer.py"
  File "..\utils\pcap_cleaner.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework"
  File "..\vmcontrol.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\impacket"
  File "impacket\__init__.py"
  File "impacket\ImpactDecoder.py"
  File "impacket\smb.py"
  File "impacket\nmb.py"
  File "impacket\structure.py"
  File "impacket\ImpactPacket.py"
  File "impacket\ntlm.py"
  File "impacket\uuid.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\impacket\dcerpc"
  File "impacket\dcerpc\__init__.py"
  File "impacket\dcerpc\conv.py"
  File "impacket\dcerpc\dcerpc.py"
  File "impacket\dcerpc\dcerpc_v4.py"
  File "impacket\dcerpc\dcom.py"
  File "impacket\dcerpc\epm.py"
  File "impacket\dcerpc\ndrutils.py"
  File "impacket\dcerpc\printer.py"
  File "impacket\dcerpc\samr.py"
  File "impacket\dcerpc\srvsvc.py"
  File "impacket\dcerpc\svcctl.py"
  File "impacket\dcerpc\transport.py"
  File "impacket\dcerpc\winreg.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\pydbg"
  File "pydbg\__init__.py"
  File "pydbg\breakpoint.py"
  File "pydbg\defines.py"
  File "pydbg\hardware_breakpoint.py"
  File "pydbg\memory_breakpoint.py"
  File "pydbg\memory_snapshot_block.py"
  File "pydbg\memory_snapshot_context.py"
  File "pydbg\my_ctypes.py"
  File "pydbg\pdx.py"
  File "pydbg\pydasm.pyd"
  File "pydbg\pydbg.py"
  File "pydbg\pydbg_client.py"
  File "pydbg\system_dll.py"
  File "pydbg\windows_h.py"
  SetOutPath "$PROGRAMFILES\Sulley Fuzzing Framework\utils"
  File "..\utils\__init__.py"
  File "..\utils\crash_binning.py"
  File "..\utils\pcap_cleaner.py"
  File "..\utils\pdml_parser.py"
  File "..\utils\crashbin_explorer.py"
  File "..\utils\ida_fuzz_library_extender.py"
SectionEnd

Section "Python" SEC02
  SetOutPath "C:\Python"
  SetOverwrite ifnewer
  ExecWait 'msiexec /i "$INSTDIR\install_files\python.msi"'
SectionEnd

Section "Pcapy" SEC03
  SetOutPath "C:\Python\Lib\site-packages\"
  SetOverwrite ifnewer
  ExecWait  "$INSTDIR\install_files\pcapy.exe"
SectionEnd

Section "WinPCAP" SEC04
  SetOutPath "$PROGRAMFILES\WinPCAP"
  SetOverwrite ifnewer
  ExecWait  "$INSTDIR\install_files\winpcap.exe"
SectionEnd

Section "ctypes" SEC05
  SetOutPath "C:\Python\Lib\site-packages\"
  SetOverwrite ifnewer
  ExecWait "$INSTDIR\install_files\ctypes.exe"
SectionEnd


Section -AdditionalIcons
  SetOutPath $INSTDIR
  WriteIniStr "$INSTDIR\${PRODUCT_NAME}.url" "InternetShortcut" "URL" "${PRODUCT_WEB_SITE}"
  CreateShortCut "$SMPROGRAMS\Sulley Fuzzing Framework\Website.lnk" "$INSTDIR\${PRODUCT_NAME}.url"
  CreateShortCut "$SMPROGRAMS\Sulley Fuzzing Framework\Uninstall.lnk" "$INSTDIR\uninst.exe"
SectionEnd

Section -Post
  WriteUninstaller "$INSTDIR\uninst.exe"
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$PROGRAMFILES\pcapy-0.10.5.win32-py2.5.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$PROGRAMFILES\pcapy-0.10.5.win32-py2.5.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
SectionEnd


Function un.onUninstSuccess
  HideWindow
  MessageBox MB_ICONINFORMATION|MB_OK "Sulley was successfully removed from your computer."
FunctionEnd

Function un.onInit
  MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Are you sure you want to completely remove Sulley and all of its components?" IDYES +2
  Abort
FunctionEnd

Section Uninstall
  Delete "$INSTDIR\${PRODUCT_NAME}.url"
  Delete "$INSTDIR\Uninstall.exe"
  Delete "$PROGRAMFILES\vmcontrol.py"
  Delete "$PROGRAMFILES\utils\pcap_cleaner.py"
  Delete "$PROGRAMFILES\utils\crashbin_explorer.py"
  Delete "$PROGRAMFILES\unit_tests\__init__.py"
  Delete "$PROGRAMFILES\unit_tests\primitives.py"
  Delete "$PROGRAMFILES\unit_tests\legos.py"
  Delete "$PROGRAMFILES\unit_tests\blocks.py"
  Delete "$PROGRAMFILES\unit_test.py"
  Delete "$PROGRAMFILES\TODO.txt"
  Delete "$PROGRAMFILES\sulley\__init__.py"
  Delete "$PROGRAMFILES\sulley\utils\__init__.py"
  Delete "$PROGRAMFILES\sulley\utils\scada.py"
  Delete "$PROGRAMFILES\sulley\utils\misc.py"
  Delete "$PROGRAMFILES\sulley\utils\dcerpc.py"
  Delete "$PROGRAMFILES\sulley\sex.py"
  Delete "$PROGRAMFILES\sulley\sessions.py"
  Delete "$PROGRAMFILES\sulley\primitives.py"
  Delete "$PROGRAMFILES\sulley\pgraph\__init__.py"
  Delete "$PROGRAMFILES\sulley\pgraph\node.py"
  Delete "$PROGRAMFILES\sulley\pgraph\graph.py"
  Delete "$PROGRAMFILES\sulley\pgraph\edge.py"
  Delete "$PROGRAMFILES\sulley\pgraph\cluster.py"
  Delete "$PROGRAMFILES\sulley\pedrpc.py"
  Delete "$PROGRAMFILES\sulley\legos\__init__.py"
  Delete "$PROGRAMFILES\sulley\legos\xdr.py"
  Delete "$PROGRAMFILES\sulley\legos\misc.py"
  Delete "$PROGRAMFILES\sulley\legos\dcerpc.py"
  Delete "$PROGRAMFILES\sulley\legos\ber.py"
  Delete "$PROGRAMFILES\sulley\blocks.py"
  Delete "$PROGRAMFILES\requests\___REQUESTS___.html"
  Delete "$PROGRAMFILES\requests\__init__.py"
  Delete "$PROGRAMFILES\requests\xbox.py"
  Delete "$PROGRAMFILES\requests\trend.py"
  Delete "$PROGRAMFILES\requests\stun.py"
  Delete "$PROGRAMFILES\requests\rendezvous.py"
  Delete "$PROGRAMFILES\requests\pds.py"
  Delete "$PROGRAMFILES\requests\oscar.py"
  Delete "$PROGRAMFILES\requests\ndmp.py"
  Delete "$PROGRAMFILES\requests\ldap.py"
  Delete "$PROGRAMFILES\requests\jabber.py"
  Delete "$PROGRAMFILES\requests\http.py"
  Delete "$PROGRAMFILES\process_monitor.py"
  Delete "$PROGRAMFILES\network_monitor.py"
  Delete "$PROGRAMFILES\LICENSE.txt"
  Delete "$PROGRAMFILES\docs\stylesheet.css"
  Delete "$PROGRAMFILES\docs\index.html"
  Delete "$PROGRAMFILES\docs\img\sulley_web_interface.gif"
  Delete "$PROGRAMFILES\docs\img\sulley.jpg"
  Delete "$PROGRAMFILES\docs\img\session_test.gif"
  Delete "$PROGRAMFILES\docs\img\pcap.gif"
  Delete "$PROGRAMFILES\docs\img\crash_paths.gif"
  Delete "$PROGRAMFILES\docs\generate_epydocs.bat"
  Delete "$PROGRAMFILES\archived_fuzzies\trillian_jabber\trillian_jabber.udg"
  Delete "$PROGRAMFILES\archived_fuzzies\trillian_jabber\trillian_jabber.crashbin"
  Delete "$PROGRAMFILES\archived_fuzzies\trillian_jabber\fuzz_trillian_jabber.py"
  Delete "$PROGRAMFILES\archived_fuzzies\trend_server_protect_5168\trend_server_protect_5168.udg"
  Delete "$PROGRAMFILES\archived_fuzzies\trend_server_protect_5168\trend_server_protect_5168.crashbin"
  Delete "$PROGRAMFILES\archived_fuzzies\trend_server_protect_5168\fuzz_trend_server_protect_5168.py"
  Delete "$PROGRAMFILES\archived_fuzzies\fuzz_trend_control_manager_20901.py"
  Delete "$PROGRAMFILES\WinPcap_4_0_1.exe"
  Delete "$PROGRAMFILES\pcapy-0.10.5.win32-py2.5.exe"
  Delete "C:\Python\a_python-2.4.3.msi"

  Delete "$SMPROGRAMS\Sulley Fuzzing Framework\Uninstall.lnk"
  Delete "$SMPROGRAMS\Sulley Fuzzing Framework\Website.lnk"
  Delete "$DESKTOP\Sulley Fuzzing Framework.lnk"
  Delete "$SMPROGRAMS\Sulley Fuzzing Framework\Sulley Fuzzing Framework.lnk"

  RMDir "C:\Python"
  RMDir "$SMPROGRAMS\Sulley Fuzzing Framework"
  RMDir "$PROGRAMFILES\utils"
  RMDir "$PROGRAMFILES\unit_tests"
  RMDir "$PROGRAMFILES\sulley\utils"
  RMDir "$PROGRAMFILES\sulley\pgraph"
  RMDir "$PROGRAMFILES\sulley\legos"
  RMDir "$PROGRAMFILES\sulley"
  RMDir "$PROGRAMFILES\requests"
  RMDir "$PROGRAMFILES\docs\img"
  RMDir "$PROGRAMFILES\docs"
  RMDir "$PROGRAMFILES\audits"
  RMDir "$PROGRAMFILES\archived_fuzzies\trillian_jabber"
  RMDir "$PROGRAMFILES\archived_fuzzies\trend_server_protect_5168"
  RMDir "$PROGRAMFILES\archived_fuzzies"

  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
  SetAutoClose true
SectionEnd