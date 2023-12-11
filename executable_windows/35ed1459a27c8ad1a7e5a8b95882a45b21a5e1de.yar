import "pe"

rule CreateInstallStubvxx
{
	meta:
		author = "malware-lu"
		description = "Detects the CreateInstallStubvxx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56 }

	condition:
		$a0 at pe.entry_point
}
