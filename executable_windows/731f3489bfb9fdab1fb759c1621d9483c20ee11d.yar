import "pe"

rule SoftwareCompressv12BGSoftwareProtectTechnologies
{
	meta:
		author = "malware-lu"
		description = "Detects SoftwareCompressv12BGSoftwareProtectTechnologies malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 1A 0F 41 00 89 44 24 1C 61 C2 04 00 E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 }

	condition:
		$a0 at pe.entry_point
}
