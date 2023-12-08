import "pe"

rule FishPEShield112116HellFish
{
	meta:
		author = "malware-lu"
		description = "Detects FishPEShield112116HellFish malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 BD FE FF FF 89 45 DC E8 E1 FD FF FF 8B 00 03 45 DC 89 45 E4 E8 DC FE FF FF 8B D8 BA 8E 4E 0E EC 8B C3 E8 2E FF FF FF 89 45 F4 BA 04 49 32 D3 8B C3 E8 1F FF FF FF 89 45 F8 BA 54 CA AF 91 8B C3 E8 10 FF FF FF 89 45 F0 BA AC 33 06 03 8B C3 E8 01 FF FF FF 89 45 EC BA 1B C6 46 79 8B C3 E8 F2 FE FF FF 89 45 E8 BA AA FC 0D 7C 8B C3 E8 E3 FE FF FF 89 45 FC 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B }
		$a1 = { 60 E8 EA FD FF FF FF D0 C3 8D 40 00 ?? 00 00 00 2C 00 00 00 [3] 00 [2] 00 00 [3] 00 00 [2] 00 [3] 00 [3] 00 ?? 00 00 00 00 [2] 00 [2] 00 00 ?? 00 00 00 00 [2] 00 00 10 00 00 [3] 00 40 [3] 00 00 [2] 00 00 [2] 00 [3] 00 40 [3] 00 00 ?? 00 00 00 [2] 00 [2] 00 00 40 }

	condition:
		$a0 or $a1 at pe.entry_point
}
