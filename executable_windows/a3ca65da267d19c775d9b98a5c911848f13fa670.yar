import "pe"

rule NullsoftInstallSystemv20a0
{
	meta:
		author = "malware-lu"
		description = "Detects Nullsoft Install System v2.0 installer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 B4 10 40 00 05 E8 03 00 00 BE E0 E3 41 00 89 44 24 10 B3 20 FF 15 28 10 40 00 68 00 04 00 00 FF 15 14 11 40 00 50 56 FF 15 10 11 40 00 80 3D E0 E3 41 00 22 75 08 80 C3 02 BE E1 E3 41 00 8A 06 8B 3D 14 12 40 00 84 C0 74 19 3A C3 74 }

	condition:
		$a0
}
