import "pe"

rule Escargot01finalMeat
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Escargot malware based on specific byte patterns at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 04 40 30 2E 31 60 68 61 [3] 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 92 [3] 8B 00 FF D0 50 B8 CD [3] 81 38 DE C0 37 13 75 2D 68 C9 [3] 6A 40 68 00 ?? 00 00 68 00 00 [2] B8 96 [3] 8B 00 FF D0 8B 44 24 F0 8B 4C 24 F4 EB 05 49 C6 04 01 40 0B C9 75 F7 BE 00 10 [2] B9 00 [2] 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE [4] E9 AC 00 00 00 8B 46 0C BB 00 00 [2] 03 C3 50 50 }

	condition:
		$a0 at pe.entry_point
}
