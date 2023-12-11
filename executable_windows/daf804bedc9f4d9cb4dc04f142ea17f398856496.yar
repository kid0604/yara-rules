import "pe"

rule Upackv0399Dwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the Upack v0.399Dwing packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [2] 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 [2] 00 00 02 00 00 00 00 00 00 ?? 00 00 00 00 00 10 00 00 ?? 00 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE [2] 00 14 00 00 00 00 [2] 00 [2] 00 00 FF 76 38 AD 50 8B 3E BE F0 [2] 00 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 [3] 00 ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 }
		$a1 = { BE B0 11 [2] AD 50 FF 76 34 EB 7C 48 01 [2] 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [3] 00 00 [2] 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 [3] 00 02 00 00 00 00 00 00 }
		$a2 = { BE B0 11 [2] AD 50 FF 76 34 EB 7C 48 01 [2] 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [3] 00 00 [2] 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 [3] 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 10 00 00 [2] 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE [3] 14 00 00 00 00 [5] 00 00 FF 76 38 AD 50 8B 3E BE F0 [3] 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 [5] 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 [4] 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 99 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}
