import "pe"

rule TheHypersprotectorTheHyper
{
	meta:
		author = "malware-lu"
		description = "Detects TheHypersprotectorTheHyper malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 EC 14 8B FC E8 14 00 00 00 [2] 01 01 [2] 01 01 [3] 00 [2] 01 01 [2] 02 01 5E E8 0D 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8B 46 04 FF 10 8B D8 E8 0D 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 07 E8 }

	condition:
		$a0 at pe.entry_point
}
