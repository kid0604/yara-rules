import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_EventViewer
{
	meta:
		description = "detects Windows exceutables potentially bypassing UAC using eventvwr.exe"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Classes\\mscfile\\shell\\open\\command" ascii wide nocase
		$s2 = "eventvwr.exe" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and all of them
}
