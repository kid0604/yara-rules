import "pe"

rule MALWARE_Win_UNKCobaltStrike
{
	meta:
		author = "ditekSHen"
		description = "Detects unknown malware, potentially CobaltStrike related"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "https://%hu.%hu.%hu.%hu:%u" ascii wide
		$s2 = "https://microsoft.com/telemetry/update.exe" ascii wide
		$s3 = "\\System32\\rundll32.exe" ascii wide
		$s4 = "api.opennicproject.org" ascii wide
		$s5 = "%s %s,%s %u" ascii wide
		$s6 = "User32.d?" ascii wide
		$s7 = "StrDupA" fullword ascii wide
		$s8 = "{6d4feed8-18fd-43eb-b5c4-696ad06fac1e}" ascii wide
		$s9 = "{ac41592a-3d21-46b7-8f21-24de30531656}" ascii wide
		$s10 = "bd526:3b.4e32.57c8.9g32.35ef41642767~" ascii wide
		$s11 = { 4b d3 91 49 a1 80 91 42 83 b6 33 28 36 6b 90 97 }
		$s12 = { 0d 4c e3 5c c9 0d 1f 4c 89 7c da a1 b7 8c ee 7c }

	condition:
		uint16(0)==0x5a4d and 6 of them
}
