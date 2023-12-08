import "pe"

rule VProtectorV10Evcasm
{
	meta:
		author = "malware-lu"
		description = "Detects VProtector V1.0 Evcasm malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
