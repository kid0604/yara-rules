import "pe"

rule MALWARE_Win_CRATPluginKeylogger
{
	meta:
		author = "ditekSHen"
		description = "Detects CRAT keylogger plugin DLL"
		clamav_sig = "MALWARE.Win.Trojan.CRAT"
		os = "windows"
		filetype = "executable"

	strings:
		$ai1 = "VM detected!" fullword wide
		$ai2 = "Sandbox detected!" fullword wide
		$ai3 = "Debug detected!" fullword wide
		$ai4 = "Analysis process detected!" fullword wide
		$s1 = "Create KeyLogMutex %s failure %d" wide
		$s2 = "Key Log Mutex already created! %s" wide
		$s3 = /KeyLogThread\s(started|finished|terminated)!/ wide
		$s4 = /KeyLog_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii

	condition:
		uint16(0)==0x5a4d and (( all of ($ai*) and 1 of ($s*)) or (3 of ($s*) and 1 of ($ai*)) or 5 of them )
}
