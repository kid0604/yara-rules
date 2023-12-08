import "pe"

rule MALWARE_Win_CRATPluginClipboardMonitor
{
	meta:
		author = "ditekSHen"
		description = "Detects CRAT Clipboad Monitor plugin DLL"
		os = "windows"
		filetype = "executable"

	strings:
		$ai1 = "VM detected!" fullword wide
		$ai2 = "Sandbox detected!" fullword wide
		$ai3 = "Debug detected!" fullword wide
		$ai4 = "Analysis process detected!" fullword wide
		$s1 = "Clipboard Monitor Mutex [%s] already created!" wide
		$s2 = "ClipboardMonitorThread started!" fullword wide
		$s3 = /MonitorClipboardThread\s(finished|terminated)!/ wide
		$s4 = /ClipboardMonitor_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii

	condition:
		uint16(0)==0x5a4d and (( all of ($ai*) and 1 of ($s*)) or (3 of ($s*) and 1 of ($ai*)) or 5 of them )
}
