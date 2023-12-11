import "pe"

rule Armadillov252_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillov252_alt_1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] E0 [4] 68 D4 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF [3] 15 38 }
		$a1 = { 55 8B EC 6A FF 68 E0 [3] 68 D4 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 38 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
