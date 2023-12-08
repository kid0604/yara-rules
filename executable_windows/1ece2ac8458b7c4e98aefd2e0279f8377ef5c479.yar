rule Miracl_crt
{
	meta:
		author = "Maxx"
		description = "Miracl crt"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 51 56 57 E8 ?? ?? ?? ?? 8B 74 24 10 8B F8 89 7C 24 08 83 7E 0C 02 0F 8C 99 01 00 00 8B 87 18 02 00 00 85 C0 0F 85 8B 01 00 00 8B 57 1C 42 8B C2 89 57 1C 83 F8 18 7D 17 C7 44 87 20 4A 00 00 00 8B 87 2C 02 00 00 85 C0 74 05 E8 ?? ?? ?? ?? 8B 46 04 8B 54 24 14 53 55 8B 08 8B 02 51 50 E8 ?? ?? ?? ?? 8B 4E 0C B8 01 00 00 00 83 C4 08 33 ED 3B C8 89 44 24 18 0F 8E C5 00 00 00 BF 04 00 00 00 8B 46 04 8B 0C 07 8B 10 8B 44 24 1C 51 52 8B 0C 07 51 E8 ?? ?? ?? ?? 8B 56 04 8B 4E 08 8B 04 }

	condition:
		$c0
}
