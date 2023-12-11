import "pe"

rule PrivatePersonalPackerPPP102ConquestOfTroycom
{
	meta:
		author = "malware-lu"
		description = "Detects the PrivatePersonalPacker (PPP) 102 Conquest of Troy malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9 }

	condition:
		$a0
}
