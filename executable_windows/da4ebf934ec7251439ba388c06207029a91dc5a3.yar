import "pe"

rule VxXRCV1015
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5E 83 [2] 53 51 1E 06 B4 99 CD 21 80 FC 21 [5] 33 C0 50 8C D8 48 8E C0 1F A1 [2] 8B }

	condition:
		$a0 at pe.entry_point
}
