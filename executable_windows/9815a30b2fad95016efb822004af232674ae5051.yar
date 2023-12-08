rule BigDig_mpModMult
{
	meta:
		author = "Maxx"
		description = "BigDig mpModMult"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 8B 44 24 0C 8B 4C 24 08 81 EC 98 01 00 00 8D 54 24 00 56 8B B4 24 B0 01 00 00 57 56 50 51 52 E8 ?? ?? ?? ?? 8B 84 24 C0 01 00 00 8B 94 24 B4 01 00 00 8D 3C 36 56 50 8D 4C 24 20 57 51 52 E8 ?? ?? ?? ?? 8D 44 24 2C 57 50 E8 ?? ?? ?? ?? 83 C4 2C 33 C0 5F 5E 81 C4 98 01 00 00 C3 }

	condition:
		$c0
}
