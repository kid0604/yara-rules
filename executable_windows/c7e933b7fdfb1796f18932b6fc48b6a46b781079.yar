import "pe"

rule PolyBoxCAnskya
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PolyBoxCAnskya malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 E4 41 00 10 E8 3A E1 FF FF 33 C0 55 68 11 44 00 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 6A 0A 68 20 44 00 10 A1 1C 71 00 10 50 E8 CC E1 [4] 85 DB 0F 84 77 01 00 00 53 A1 1C 71 00 10 50 E8 1E E2 FF FF 8B F0 85 F6 0F 84 61 01 00 00 53 A1 1C 71 00 10 50 E8 E0 E1 FF FF 85 C0 0F 84 4D 01 00 00 50 E8 DA E1 FF FF 8B D8 85 DB 0F 84 3D 01 00 00 56 B8 70 80 00 10 B9 01 00 00 00 8B 15 98 41 00 10 E8 9E DE FF FF 83 C4 04 A1 70 80 00 10 8B CE 8B D3 E8 E1 E1 FF FF 6A 00 6A 00 A1 70 80 00 10 B9 30 44 00 10 8B D6 E8 F8 FD FF FF }

	condition:
		$a0
}
