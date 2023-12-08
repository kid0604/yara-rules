import "pe"

rule Armadillov252b2
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillov252b2 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 B0 [3] 68 60 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 24 }

	condition:
		$a0 at pe.entry_point
}
