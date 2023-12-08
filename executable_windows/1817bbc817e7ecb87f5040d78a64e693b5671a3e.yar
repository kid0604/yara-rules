rule RsaRef2_RsaPrivateEncrypt
{
	meta:
		author = "Maxx"
		description = "RsaRef2 RsaPrivateEncrypt"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 8B 44 24 14 8B 54 24 10 81 EC 80 00 00 00 8D 4A 0B 56 8B 30 83 C6 07 C1 EE 03 3B CE 76 0D B8 06 04 00 00 5E 81 C4 80 00 00 00 C3 8B CE B8 02 00 00 00 2B CA C6 44 24 04 00 49 C6 44 24 05 01 3B C8 76 23 53 55 8D 69 FE 57 8B CD 83 C8 FF 8B D9 8D 7C 24 12 C1 E9 02 F3 AB 8B CB 83 E1 03 F3 AA 8D 45 02 5F 5D 5B 52 8B 94 24 94 00 00 00 C6 44 04 08 00 8D 44 04 09 52 50 E8 ?? ?? ?? ?? 8B 8C 24 A4 00 00 00 8B 84 24 98 00 00 00 51 8B 8C 24 98 00 00 00 8D 54 24 14 56 52 50 51 E8 }

	condition:
		$c0
}
