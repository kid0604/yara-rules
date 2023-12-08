import "pe"

rule yodasProtectorV101AshkbizDanehkar
{
	meta:
		author = "malware-lu"
		description = "Yoda's Protector v1.01 by Ashkbiz Danehkar"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED D5 E4 41 00 8B D5 81 C2 23 E5 41 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 }

	condition:
		$a0 at pe.entry_point
}
