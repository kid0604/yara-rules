import "pe"

rule PEXv099
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 01 [4] 83 C4 04 E8 01 [4] 5D 81 }

	condition:
		$a0 at pe.entry_point
}
