import "pe"

rule PECryptv102
{
	meta:
		author = "malware-lu"
		description = "Detects a specific encryption pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [4] 5B 83 EB 05 EB 04 52 4E 44 }

	condition:
		$a0 at pe.entry_point
}
