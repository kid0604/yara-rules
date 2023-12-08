import "pe"

rule UnoPiX075BaGiE
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 07 00 00 00 61 68 [2] 40 00 C3 83 04 24 18 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 61 }

	condition:
		$a0 at pe.entry_point
}
