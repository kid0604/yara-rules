import "pe"

rule MSLRHv032afakeBJFNT13emadicius
{
	meta:
		author = "malware-lu"
		description = "Detects a fake entry point in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 EB 02 C7 05 EB 02 CD 20 E8 03 00 00 00 E9 EB 04 58 40 50 C3 61 9D 1F EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
		$a0 at pe.entry_point
}
