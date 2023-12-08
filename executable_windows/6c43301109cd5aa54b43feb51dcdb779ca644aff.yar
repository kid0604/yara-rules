import "pe"

rule SDProtectRandyLi
{
	meta:
		author = "malware-lu"
		description = "Detects the SDProtectRandyLi malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 }

	condition:
		$a0 at pe.entry_point
}
