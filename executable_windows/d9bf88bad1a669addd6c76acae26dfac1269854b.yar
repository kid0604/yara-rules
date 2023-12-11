import "pe"

rule RLPackAp0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPackAp0x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 CD 09 00 00 89 85 14 0A 00 00 EB 14 60 FF B5 14 0A }
		$a1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 EB 09 00 00 89 85 3A 0A 00 00 EB 14 60 FF B5 3A 0A }
		$a2 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 0C 00 00 EB 03 0C 00 00 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 47 02 00 00 EB 03 15 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 9B 0A }
		$a3 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 [4] 6A 40 68 [4] 68 [4] 6A 00 FF 95 CD 09 00 00 89 85 [4] EB 14 60 FF B5 14 0A }
		$a4 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 [4] 6A 40 68 [4] 68 [4] 6A 00 FF 95 EB 09 00 00 89 85 [4] EB 14 60 FF B5 3A 0A }
		$a5 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 [3] EB 03 [3] 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 [4] EB 03 [3] 6A 40 68 [4] 68 [4] 6A 00 FF 95 9B 0A }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point or $a4 at pe.entry_point or $a5 at pe.entry_point
}
