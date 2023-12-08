import "pe"

rule SDProtector1xRandyLi
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of SDProtector1xRandyLi malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 }

	condition:
		$a0 at pe.entry_point
}
