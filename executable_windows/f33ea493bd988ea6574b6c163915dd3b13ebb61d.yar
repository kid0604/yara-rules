import "pe"

rule Armadillov275a
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo v2.75a malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 68 [3] 68 D0 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 28 [3] 33 D2 8A D4 89 15 24 }

	condition:
		$a0 at pe.entry_point
}
