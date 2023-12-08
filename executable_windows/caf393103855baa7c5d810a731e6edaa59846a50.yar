import "pe"

rule UnnamedScrambler21Beta211p0ke
{
	meta:
		author = "malware-lu"
		description = "Detects the UnnamedScrambler21Beta211p0ke malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC B9 15 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? 3A [2] E8 ?? EE FF FF 33 C0 55 68 ?? 43 [2] 64 FF 30 64 89 20 BA ?? 43 [2] B8 E4 64 [2] E8 0F FD FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? EE FF FF BA E8 64 [2] 8B C3 8B 0D E4 64 [2] E8 ?? D7 FF FF B8 F8 [3] BA 04 00 00 00 E8 ?? EF FF FF 33 C0 A3 F8 [3] BB [4] C7 45 EC E8 64 [2] C7 45 E8 [4] C7 45 E4 [4] BE [4] BF [4] B8 E0 [3] BA 04 00 00 00 E8 ?? EF FF FF 68 F4 01 00 00 E8 ?? EE FF FF 83 7B 04 00 75 0B 83 3B 00 0F 86 ?? 07 00 00 EB 06 0F 8E ?? 07 00 00 8B 03 8B D0 B8 E4 [3] E8 ?? E5 FF FF B8 E4 [3] E8 ?? E3 FF FF 8B D0 8B 45 EC 8B 0B E8 }

	condition:
		$a0
}
