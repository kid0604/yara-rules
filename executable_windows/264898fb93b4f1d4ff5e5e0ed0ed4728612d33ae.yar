rule RsaRef2_RsaPublicEncrypt
{
	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPublicEncrypt"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 8B 44 24 14 81 EC 84 00 00 00 53 8B 9C 24 98 00 00 00 57 8B 38 83 C7 07 8D 4B 0B C1 EF 03 3B CF 76 0E 5F B8 06 04 00 00 5B 81 C4 84 00 00 00 C3 8B D7 55 2B D3 56 BE 02 00 00 00 C6 44 24 14 00 8D 6A FF C6 44 24 15 02 3B EE 76 28 8B 84 24 AC 00 00 00 8D 4C 24 13 50 6A 01 51 E8 ?? ?? ?? ?? 8A 44 24 1F 83 C4 0C 84 C0 74 E1 88 44 34 14 46 3B F5 72 D8 8B 94 24 A0 00 00 00 53 8D 44 34 19 52 50 C6 44 34 20 00 E8 ?? ?? ?? ?? 8B 8C 24 B4 00 00 00 8B 84 24 A8 00 00 00 51 8B 8C 24 A8 00 }

	condition:
		$c0
}
