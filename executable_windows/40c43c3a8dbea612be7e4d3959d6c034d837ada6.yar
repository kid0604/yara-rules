import "pe"

rule OpenSourceCodeCrypterp0ke
{
	meta:
		author = "malware-lu"
		description = "Detects the OpenSourceCodeCrypterp0ke malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC B9 09 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 34 44 40 00 E8 28 F8 FF FF 33 C0 55 68 9F 47 40 00 64 FF 30 64 89 20 BA B0 47 40 00 B8 1C 67 40 00 E8 07 FD FF FF 8B D8 85 DB 75 07 6A 00 E8 C2 F8 FF FF BA 28 67 40 00 8B C3 8B 0D 1C 67 40 00 E8 F0 E0 FF FF BE 01 00 00 00 B8 2C 68 40 00 E8 E1 F0 FF FF BF 0A 00 00 00 8D 55 EC 8B C6 E8 92 FC FF FF 8B 4D EC B8 2C 68 40 00 BA BC 47 40 00 E8 54 F2 FF FF A1 2C 68 40 00 E8 52 F3 FF FF 8B D0 B8 20 67 40 00 E8 A2 FC FF FF 8B D8 85 DB 0F 84 52 02 00 00 B8 24 67 40 00 8B 15 20 67 40 00 E8 78 F4 FF FF B8 24 67 40 00 E8 7A F3 FF FF 8B D0 8B C3 8B 0D 20 67 40 00 E8 77 E0 FF FF 8D 55 E8 A1 24 67 40 00 E8 42 FD FF FF 8B 55 E8 B8 24 67 40 00 }

	condition:
		$a0
}
