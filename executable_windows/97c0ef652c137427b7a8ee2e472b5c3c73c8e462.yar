import "pe"

rule VxPhoenix927
{
	meta:
		author = "malware-lu"
		description = "Detects VxPhoenix927 malware based on specific string pattern at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 5E 81 C6 [2] BF 00 01 B9 04 00 F3 A4 E8 }

	condition:
		$a0 at pe.entry_point
}
