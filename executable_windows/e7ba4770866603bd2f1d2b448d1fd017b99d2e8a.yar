import "pe"

rule Crunchv5BitArts
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Crunch v5 BitArts malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 FC 07 00 00 89 85 E8 07 00 00 FF 74 24 2C E8 20 02 00 00 0F 82 94 06 00 00 E8 F3 04 00 00 49 0F 88 88 06 00 00 8B B5 E8 07 00 }

	condition:
		$a0 at pe.entry_point
}
