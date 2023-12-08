rule QakBotLoader_alt_1
{
	meta:
		author = "kevoreilly"
		description = "QakBot Export Selection"
		cape_options = "export=$export1,export=$export2,export=$export3"
		hash = "6f99171c95a8ed5d056eeb9234dbbee123a6f95f481ad0e0a966abd2844f0e1a"
		os = "windows"
		filetype = "executable"

	strings:
		$export1 = {55 8B EC 83 EC 50 (3A|66 3B) ?? 74}
		$export2 = {55 8B EC 3A ?? 74 [8-16] 74 [6-16] EB}
		$export3 = {55 8B EC 66 3B ?? 74 [3-5] 74}
		$wind = {(66 3B|3A) ?? 74 [1-14] BB 69 04 00 00 53 E? [5-20] 74}
		$getteb = {EB 00 55 8B EC 66 3B E4 74 ?? [1-5] 64 A1 18 00 00 00 5D EB}

	condition:
		uint16(0)==0x5A4D and ( any of ($export*)) and ($wind or $getteb)
}
