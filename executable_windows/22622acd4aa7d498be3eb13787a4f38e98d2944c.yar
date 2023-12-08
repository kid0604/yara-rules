import "pe"

rule eXPressorv12CGSoftLabs
{
	meta:
		author = "malware-lu"
		description = "Detects eXPressor v1.2 by CGSoftLabs"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 45 78 50 72 2D 76 2E 31 2E 32 2E }
		$a1 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 [4] 2B 05 84 [3] A3 [4] 83 3D [4] 00 74 16 A1 [4] 03 05 80 [3] 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 [4] 01 00 00 00 68 04 }
		$a2 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 [4] 2B 05 84 [3] A3 [4] 83 3D [4] 00 74 16 A1 [4] 03 05 80 [3] 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 [4] 01 00 00 00 68 04 01 00 00 8D 85 F0 FE FF FF 50 6A 00 FF 15 }

	condition:
		$a0 or $a1 at pe.entry_point or $a2 at pe.entry_point
}
