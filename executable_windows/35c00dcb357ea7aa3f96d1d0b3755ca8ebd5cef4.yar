import "pe"

rule Enigmaprotector112VladimirSukhov
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting Enigmaprotector112VladimirSukhov malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED [35] E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 FF 15 89 C4 61 EB 2E EA EB 2B 83 04 24 03 EB 01 00 31 C0 EB 01 85 64 FF 30 EB 01 83 64 89 20 EB 02 CD 20 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 90 58 61 EB 01 3E EB 04 [4] B8 [35] E8 01 00 00 00 9A 83 C4 04 01 E8 [31] E8 01 00 00 00 9A 83 C4 04 05 F6 01 00 00 [31] E8 01 00 00 00 9A 83 C4 04 B9 44 1A }

	condition:
		$a0
}
