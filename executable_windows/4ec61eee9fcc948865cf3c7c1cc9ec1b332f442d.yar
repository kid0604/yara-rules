import "pe"

rule SoftwareCompressBGSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the SoftwareCompressBGSoftware malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 }

	condition:
		$a0 at pe.entry_point
}
