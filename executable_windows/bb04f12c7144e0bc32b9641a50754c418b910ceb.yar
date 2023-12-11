import "pe"

rule MALWARE_Win_CRATPluginScreenCapture
{
	meta:
		author = "ditekSHen"
		description = "Detects CRAT Screen Capture plugin DLL"
		os = "windows"
		filetype = "executable"

	strings:
		$ai1 = "VM detected!" fullword wide
		$ai2 = "Sandbox detected!" fullword wide
		$ai3 = "Debug detected!" fullword wide
		$ai4 = "Analysis process detected!" fullword wide
		$s1 = "User is inactive!, give up capture" wide
		$s2 = "Capturing screen..." wide
		$s3 = "%s\\P%02d%lu.tmp" fullword wide
		$s4 = "CloseHandle ScreenCaptureMutex failure! %d" fullword wide
		$s5 = "ScreenCaptureMutex already created! %s" fullword wide
		$s6 = "Create ScreenCaptureMutex %s failure %d" fullword wide
		$s7 = /ScreenCaptureThread\s(finished|terminated)!/ wide
		$s8 = /ScreenCapture_(x64|x32|Win64|Win32)_DllRelease\.dll/ fullword ascii

	condition:
		uint16(0)==0x5a4d and (( all of ($ai*) and 1 of ($s*)) or (3 of ($s*) and 1 of ($ai*)) or 6 of them )
}
