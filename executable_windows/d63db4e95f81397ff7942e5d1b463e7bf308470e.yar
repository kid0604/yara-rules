import "pe"

rule Armadillov25xv26x
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo v2.5 and v2.6 packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 [3] 33 D2 8A D4 89 15 EC }

	condition:
		$a0 at pe.entry_point
}
