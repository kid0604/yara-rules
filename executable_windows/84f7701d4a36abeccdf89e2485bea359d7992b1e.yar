import "pe"

rule Armadillov253
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillov253 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 40 [3] 68 54 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 58 [3] 33 D2 8A D4 89 15 EC }
		$a1 = { 55 8B EC 6A FF 68 [4] 40 [4] 68 54 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF [3] 15 58 33 D2 8A D4 89 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
