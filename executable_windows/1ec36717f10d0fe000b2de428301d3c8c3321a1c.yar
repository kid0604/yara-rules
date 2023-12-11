import "pe"

rule MZ0oPE106bTaskFall
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 [4] C3 }
		$a1 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 [4] C3 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4C 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
