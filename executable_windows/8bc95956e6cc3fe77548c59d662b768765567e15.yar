import "pe"

rule WiseInstallerStub
{
	meta:
		author = "malware-lu"
		description = "Detects Wise Installer Stub malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF }
		$a1 = { 55 8B EC 81 EC ?? 04 00 00 53 56 57 6A [7] FF 15 [2] 40 00 [56] 80 ?? 20 }
		$a2 = { 55 8B EC 81 EC [2] 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2
}
