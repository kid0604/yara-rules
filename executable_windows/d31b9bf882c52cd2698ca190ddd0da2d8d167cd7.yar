import "pe"

rule eXPressorV1451CGSoftLabs
{
	meta:
		author = "malware-lu"
		description = "Detects eXPressor v1.45 by CGSoftLabs"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 [2] 00 05 00 [2] 00 A3 08 [2] 00 A1 08 [2] 00 B9 81 [2] 00 2B 48 18 89 0D 0C [2] 00 83 3D }

	condition:
		$a0 at pe.entry_point
}
