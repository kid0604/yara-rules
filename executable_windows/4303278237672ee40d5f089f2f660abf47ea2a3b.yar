import "pe"

rule eXPressorPacK150XCGSoftLabs
{
	meta:
		author = "malware-lu"
		description = "Detects eXPressorPacK150XCGSoftLabs malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC [4] 53 56 57 83 A5 [5] F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C ?? 75 23 8B 45 08 A3 [4] 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF 15 [4] A3 [4] EB 04 }

	condition:
		$a0 at pe.entry_point
}
