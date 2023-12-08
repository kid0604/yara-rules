import "pe"

rule VProtectorV11vcasm
{
	meta:
		author = "malware-lu"
		description = "Detects VProtector V11 virtualization-based anti-debugging technique"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 1A ED 41 00 B9 EC EB 41 00 50 51 E8 74 00 00 00 E8 51 6A 00 00 58 83 E8 10 B9 B3 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
