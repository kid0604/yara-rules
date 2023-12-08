import "pe"

rule VProtectorV10Bvcasm
{
	meta:
		author = "malware-lu"
		description = "Detects VProtector V1.0 Bvcasm malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

	condition:
		$a0 at pe.entry_point
}
