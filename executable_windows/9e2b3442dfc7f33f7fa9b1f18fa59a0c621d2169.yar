import "pe"

rule PEPROTECT09
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 CF 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

	condition:
		$a0 at pe.entry_point
}
