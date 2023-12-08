import "pe"

rule Armadillov172v173
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo version 17.2 and 17.3"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 [2] 68 F4 86 [2] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}
