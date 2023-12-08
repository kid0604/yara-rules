import "pe"

rule Armadillov310
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo v3.10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1 }

	condition:
		$a0 at pe.entry_point
}
