import "pe"

rule APEX_CBLTApex40500mhz
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 [4] B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 }

	condition:
		$a0 at pe.entry_point
}
