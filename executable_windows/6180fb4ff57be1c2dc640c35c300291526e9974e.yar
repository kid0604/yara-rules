import "pe"

rule XCRv012
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 9C E8 [4] 8B DD 5D 81 ED [4] 89 9D }

	condition:
		$a0 at pe.entry_point
}
