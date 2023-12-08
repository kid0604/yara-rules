rule FGint_MulByInt
{
	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "FGint MulByInt"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 53 56 57 55 83 C4 E8 89 4C 24 04 8B EA 89 04 24 8B 04 24 8B 40 04 8B 00 89 44 24 08 8B 44 24 08 83 C0 02 50 8D 45 04 B9 01 00 00 00 8B 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 C4 04 33 F6 8B 7C 24 08 85 FF 76 6D BB 01 00 00 00 8B 04 24 8B 40 04 8B 04 98 33 D2 89 44 24 10 89 54 24 14 8B 44 24 04 33 D2 52 50 8B 44 24 18 8B 54 24 1C ?? ?? ?? ?? ?? 89 44 24 10 89 54 24 14 8B C6 33 D2 03 44 24 10 13 54 24 14 89 44 24 10 89 54 24 14 8B 44 24 10 25 FF FF FF 7F 8B 55 04 89 04 9A 8B 44 24 10 8B 54 24 14 0F AC D0 1F C1 EA 1F 8B F0 43 4F 75 98 }

	condition:
		$c0
}
