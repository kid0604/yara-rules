import "pe"

rule DEF10bartxt
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE [2] 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 [2] 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
