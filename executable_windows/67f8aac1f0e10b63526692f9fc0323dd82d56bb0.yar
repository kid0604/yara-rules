import "pe"

rule Armadillov250b3
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo v2.50b3 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 B8 [3] 68 F8 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 20 [3] 33 D2 8A D4 89 15 D0 }

	condition:
		$a0 at pe.entry_point
}
