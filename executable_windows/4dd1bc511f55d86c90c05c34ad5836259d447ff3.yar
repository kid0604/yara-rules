import "pe"

rule VxHafen1641
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 01 [3] CE CC 25 [2] 25 [2] 25 [2] 40 51 D4 [3] CC 47 CA [2] 46 8A CC 44 88 CC }

	condition:
		$a0 at pe.entry_point
}
