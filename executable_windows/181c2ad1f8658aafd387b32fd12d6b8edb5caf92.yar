rule BigDig_spModExpB
{
	meta:
		author = "Maxx"
		description = "BigDig spModExpB"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 53 8B 5C 24 10 55 56 BE 00 00 00 80 85 F3 75 04 D1 EE 75 F8 8B 6C 24 14 8B C5 D1 EE 89 44 24 18 74 48 57 8B 7C 24 20 EB 04 8B 44 24 1C 57 50 50 8D 44 24 28 50 E8 ?? ?? ?? ?? 83 C4 10 85 F3 74 14 8B 4C 24 1C 57 55 8D 54 24 24 51 52 E8 ?? ?? ?? ?? 83 C4 10 D1 EE 75 D0 8B 44 24 14 8B 4C 24 1C 5F 5E 89 08 5D 33 C0 5B C3 8B 54 24 10 5E 5D 5B 89 02 33 C0 C3 }

	condition:
		$c0
}
