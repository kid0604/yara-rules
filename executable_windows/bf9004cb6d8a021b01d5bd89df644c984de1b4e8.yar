import "pe"

rule PESpinv11Cyberbob
{
	meta:
		author = "malware-lu"
		description = "Detects PESpinv11Cyberbob malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
		$a0 at pe.entry_point
}
