import "pe"

rule PolyBoxDAnskya
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PolyBoxDAnskya malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 33 C9 51 51 51 51 51 53 33 C0 55 68 84 2C 40 00 64 FF 30 64 89 20 C6 45 FF 00 B8 B8 46 40 00 BA 24 00 00 00 E8 8C F3 FF FF 6A 24 BA B8 46 40 00 8B 0D B0 46 40 00 A1 94 46 40 00 E8 71 FB FF FF 84 C0 0F 84 6E 01 00 00 8B 1D D0 46 40 00 8B C3 83 C0 24 03 05 D8 46 40 00 3B 05 B4 46 40 00 0F 85 51 01 00 00 8D 45 F4 BA B8 46 40 00 B9 10 00 00 00 E8 A2 EC FF FF 8B 45 F4 BA 9C 2C 40 00 E8 F1 ED FF FF }

	condition:
		$a0
}
