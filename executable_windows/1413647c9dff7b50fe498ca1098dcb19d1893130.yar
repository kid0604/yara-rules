import "pe"

rule Armadillov4000053SiliconRealmsToolworks
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo v4.00.0053 Silicon Realms Toolworks"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 20 8B 4B 00 68 80 E4 48 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4B 00 33 D2 8A D4 89 15 A4 A1 4B 00 8B C8 81 E1 FF 00 00 00 89 0D A0 A1 4B 00 C1 E1 08 03 CA 89 0D 9C A1 4B 00 C1 E8 10 A3 98 A1 }

	condition:
		$a0 at pe.entry_point
}
