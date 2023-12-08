import "pe"

rule PassEXEv20
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 06 1E 0E 0E 07 1F BE [2] B9 [2] 87 14 81 [3] EB ?? C7 [3] 84 00 87 [3] FB 1F 58 4A }

	condition:
		$a0 at pe.entry_point
}
