import "pe"

rule Armadillov252beta2
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo v2.52 beta 2 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] B0 [4] 68 60 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF [3] 15 24 }

	condition:
		$a0 at pe.entry_point
}
