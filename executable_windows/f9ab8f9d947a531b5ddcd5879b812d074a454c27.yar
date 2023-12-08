import "pe"

rule eXPressorv1451CGSoftLabs
{
	meta:
		author = "malware-lu"
		description = "Detects eXPressor v1.451 by CGSoftLabs"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 [3] 05 00 [3] A3 08 [3] A1 08 [3] B9 81 [3] 2B 48 18 89 0D 0C [3] 83 3D 10 [3] 00 74 16 A1 08 [3] 8B 0D 0C [3] 03 48 14 }
		$a1 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 [3] 05 00 [3] A3 08 [3] A1 08 [3] B9 81 [3] 2B 48 18 89 0D 0C [3] 83 3D 10 [3] 00 74 16 A1 08 [3] 8B 0D 0C [3] 03 48 14 89 4D CC }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
