import "pe"

rule VxEddie1800
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5E 81 EE [2] FC 2E [4] 4D 5A [2] FA 8B E6 81 C4 [2] FB 3B [5] 50 06 56 1E 8B FE 33 C0 50 8E D8 C4 [3] 2E [4] 2E }

	condition:
		$a0 at pe.entry_point
}
