import "pe"

rule ORiENV212FisunAV
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE CD 0D }

	condition:
		$a0 at pe.entry_point
}
