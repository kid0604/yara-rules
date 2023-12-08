rule SUSP_WER_Suspicious_Crash_Directory
{
	meta:
		description = "Detects a crashed application executed in a suspicious directory"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1185585050059976705"
		date = "2019-10-18"
		score = 45
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "ReportIdentifier=" wide
		$a2 = ".Name=Fault Module Name" wide
		$a3 = "AppPath=" wide nocase
		$l1 = "AppPath=C:\\Windows\\" wide nocase
		$l2 = "AppPath=C:\\Program" wide nocase
		$l3 = "AppPath=C:\\Python" wide nocase
		$l4 = "AppPath=C:\\Users\\" wide nocase
		$s6 = "AppPath=C:\\Users\\Public\\" nocase wide
		$s7 = "AppPath=C:\\Users\\Default\\" nocase wide
		$s8 = /AppPath=C:\\Users\\[^\\]{1,64}\\AppData\\(Local|Roaming)\\[^\\]{1,64}\.exe/ wide nocase

	condition:
		( uint32be(0)==0x56006500 or uint32be(0)==0xfffe5600) and all of ($a*) and ( not 1 of ($l*) or 1 of ($s*))
}
