import "pe"

rule VxEinstein
{
	meta:
		author = "malware-lu"
		description = "Detects VxEinstein malware by checking for specific byte sequence at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 42 CD 21 72 31 B9 6E 03 33 D2 B4 40 CD 21 72 19 3B C1 75 15 B8 00 42 }

	condition:
		$a0 at pe.entry_point
}
