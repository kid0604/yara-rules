rule INDICATOR_OLE_Suspicious_ActiveX
{
	meta:
		description = "detects OLE documents with suspicious ActiveX content"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$vb = "\\VBE7.DLL" ascii
		$ax1 = "_Layout" ascii
		$ax2 = "MultiPage1_" ascii
		$ax3 = "_MouseMove" ascii
		$ax4 = "_MouseHover" ascii
		$ax5 = "_MouseLeave" ascii
		$ax6 = "_MouseEnter" ascii
		$ax7 = "ImageCombo21_Change" ascii
		$ax8 = "InkEdit1_GotFocus" ascii
		$ax9 = "InkPicture1_" ascii
		$ax10 = "SystemMonitor1_" ascii
		$ax11 = "WebBrowser1_" ascii
		$ax12 = "_Click" ascii
		$kw1 = "CreateObject" ascii
		$kw2 = "CreateTextFile" ascii
		$kw3 = ".SpawnInstance_" ascii
		$kw4 = "WScript.Shell" ascii
		$kw5 = { 43 68 72 [0-2] 41 73 63 [0-2] 4d 69 64 }
		$kw6 = { 43 68 [0-2] 72 24 28 40 24 28 22 26 48 }
		$kw7 = { 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 }

	condition:
		uint16(0)==0xcfd0 and $vb and 1 of ($ax*) and 2 of ($kw*)
}
