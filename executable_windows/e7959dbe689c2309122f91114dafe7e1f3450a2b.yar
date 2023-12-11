import "pe"

rule eXPressorv120b
{
	meta:
		author = "malware-lu"
		description = "Detects eXPressor v1.20b packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 [3] 00 2B 05 84 [2] 00 A3 [3] 00 83 3D [3] 00 00 74 16 A1 [3] 00 03 05 80 [2] 00 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 [3] 00 01 00 00 00 68 04 }

	condition:
		$a0
}
