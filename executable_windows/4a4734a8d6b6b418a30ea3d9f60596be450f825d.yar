import "pe"

rule WiseInstallerStubv11010291
{
	meta:
		author = "malware-lu"
		description = "Detects Wise Installer Stub v1.1.0.10291"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 }

	condition:
		$a0 at pe.entry_point
}
