import "pe"

rule EXERefactorV01random
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC 90 0B 00 00 53 56 57 E9 58 8C 01 00 55 53 43 41 54 49 4F 4E }

	condition:
		$a0 at pe.entry_point
}
