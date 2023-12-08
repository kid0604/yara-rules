import "pe"

rule UnnamedScrambler251Beta2252p0ke
{
	meta:
		author = "malware-lu"
		description = "Detects UnnamedScrambler251Beta2252p0ke malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 [2] 40 00 E8 ?? EA FF FF 33 C0 55 68 [2] 40 00 64 FF 30 64 89 20 BA [2] 40 00 B8 [2] 40 00 E8 63 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 [2] FF FF BA [2] 40 00 8B C3 8B 0D [2] 40 00 E8 [2] FF FF C7 05 [2] 40 00 0A 00 00 00 BB [2] 40 00 BE [2] 40 00 BF [2] 40 00 B8 [2] 40 00 BA 04 00 00 00 E8 ?? EB FF FF 83 3B 00 74 04 33 C0 89 03 8B D7 8B C6 E8 0A F3 FF FF 89 03 83 3B 00 0F 84 F7 04 00 00 B8 [2] 40 00 8B 16 E8 ?? E1 FF FF B8 [2] 40 00 E8 ?? E0 FF FF 8B D0 8B 03 8B 0E E8 [2] FF FF 8B C7 A3 [2] 40 00 8D 55 EC 33 C0 E8 ?? D3 FF FF 8B 45 EC B9 [2] 40 00 BA [2] 40 00 E8 8B ED FF FF 3C 01 75 2B A1 }

	condition:
		$a0
}
