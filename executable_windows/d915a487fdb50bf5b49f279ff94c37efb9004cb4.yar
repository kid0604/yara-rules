import "pe"

rule MALWARE_Win_UNK05
{
	meta:
		author = "ditekSHen"
		description = "Detects potential BazarLoader"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "/api/get" ascii wide
		$s2 = "PARENTCMDLINE" fullword ascii
		$s3 = "https://microsoft.com/telemetry/update.exe" ascii wide
		$s4 = "api.opennicproject.org" fullword ascii wide
		$s5 = "https://%hu.%hu.%hu.%hu:%u" fullword ascii wide
		$s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36 Edg/94.0.992.31" ascii wide
		$s7 = "PARENTJOBID" fullword ascii wide
		$s8 = "\\System32\\rundll32.exe" fullword ascii wide
		$s9 = "{ccc38b40-5b04-4fb1-a684-07c7e448d4df}" fullword ascii wide
		$s10 = "{065f6686-990b-46fc-829c-a53ec188a723}" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and 6 of them
}
