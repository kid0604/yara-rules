import "pe"

rule Armadillov19x
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillov19x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 98 [3] 68 10 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 }

	condition:
		$a0 at pe.entry_point
}
