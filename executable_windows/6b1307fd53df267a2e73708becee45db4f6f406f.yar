import "pe"

rule HardlockdongleAlladin
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Hardlock dongle Alladin malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 00 00 00 00 5C 5C 2E 5C 46 45 6E 74 65 44 65 76 }

	condition:
		$a0 at pe.entry_point
}
