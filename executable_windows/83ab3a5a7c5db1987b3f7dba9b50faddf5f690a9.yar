import "pe"

rule SDProtectorBasicProEdition110RandyLi
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting SDProtector Basic Pro Edition 1.10 by Randy Li"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 50 83 EC 08 64 A1 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 83 C4 08 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 64 }

	condition:
		$a0 at pe.entry_point
}
