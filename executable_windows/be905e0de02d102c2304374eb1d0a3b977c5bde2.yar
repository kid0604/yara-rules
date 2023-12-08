import "pe"

rule Apex_cbeta500mhz
{
	meta:
		author = "malware-lu"
		description = "Detects the Apex_cbeta500mhz malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 [4] B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
