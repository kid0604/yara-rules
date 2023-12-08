rule BigDig_spModMult
{
	meta:
		author = "Maxx"
		description = "BigDig spModMult"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 8B 44 24 0C 8B 4C 24 08 83 EC 08 8D 54 24 00 50 51 52 E8 ?? ?? ?? ?? 8B 44 24 24 6A 02 8D 4C 24 10 50 51 E8 ?? ?? ?? ?? 8B 54 24 24 89 02 33 C0 83 C4 20 C3 }

	condition:
		$c0
}
