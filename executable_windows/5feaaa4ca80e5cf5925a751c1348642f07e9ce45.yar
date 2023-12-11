import "pe"

rule CrunchPEv40
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the CrunchPEv40 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 10 [16] 55 E8 [4] 5D 81 ED 18 [3] 8B C5 55 60 9C 2B 85 E9 06 [2] 89 85 E1 06 [2] FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 }

	condition:
		$a0
}
