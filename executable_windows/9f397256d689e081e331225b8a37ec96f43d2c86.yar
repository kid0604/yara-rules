rule BigDig_bpInit
{
	meta:
		author = "Maxx"
		description = "BigDig bpInit"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { 56 8B 74 24 0C 6A 04 56 E8 ?? ?? ?? ?? 8B C8 8B 44 24 10 83 C4 08 85 C9 89 08 75 04 33 C0 5E C3 89 70 08 C7 40 04 00 00 00 00 5E C3 }

	condition:
		$c0
}
