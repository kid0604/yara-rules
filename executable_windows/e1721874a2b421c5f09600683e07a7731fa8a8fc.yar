import "pe"

rule Armadillo50DllSiliconRealmsToolworks
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo 5.0 DLL used by Silicon Realms Toolworks"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 7C 24 08 01 75 05 E8 DE 4B 00 00 FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ED FE FF FF 59 C2 0C 00 6A 0C 68 [4] E8 E5 24 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 8F 15 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 20 15 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D [4] 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 [4] 77 37 6A 04 E8 D7 23 00 00 59 89 7D FC FF 75 08 E8 EC 53 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 2B C5 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 [4] FF 15 [4] 8B D8 3B DF 75 4C 39 3D [4] 74 33 56 E8 19 ED FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 7D 22 00 00 59 C3 }

	condition:
		$a0 at pe.entry_point
}
