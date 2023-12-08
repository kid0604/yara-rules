rule BigDig_mpModulo
{
	meta:
		author = "Maxx"
		description = "BigDig mpModulo"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 8B 44 24 10 81 EC 30 03 00 00 8B 8C 24 38 03 00 00 8D 54 24 00 56 8B B4 24 40 03 00 00 57 8B BC 24 4C 03 00 00 57 50 56 51 8D 84 24 B0 01 00 00 52 50 E8 ?? ?? ?? ?? 8B 94 24 54 03 00 00 8D 4C 24 20 57 51 52 E8 ?? ?? ?? ?? 8D 44 24 2C 56 50 E8 ?? ?? ?? ?? 8D 8C 24 CC 01 00 00 56 51 E8 ?? ?? ?? ?? 83 C4 34 33 C0 5F 5E 81 C4 30 03 00 00 C3 }

	condition:
		$c0
}
