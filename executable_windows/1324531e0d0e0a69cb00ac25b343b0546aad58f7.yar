import "pe"

rule PCPECalpha
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 51 52 56 57 55 E8 [4] 5D 8B CD 81 [4] ?? 2B [4] ?? 83 }

	condition:
		$a0 at pe.entry_point
}
