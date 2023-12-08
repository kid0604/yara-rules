import "pe"

rule NullsoftInstallSystemv1xx
{
	meta:
		author = "malware-lu"
		description = "Detects Nullsoft Install System v1.xx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 }
		$a1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
