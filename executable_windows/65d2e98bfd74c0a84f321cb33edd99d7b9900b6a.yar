import "pe"

rule VxCaz1204
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10 }

	condition:
		$a0 at pe.entry_point
}
