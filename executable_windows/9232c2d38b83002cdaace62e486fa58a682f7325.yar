import "pe"

rule Crunchv40
{
	meta:
		author = "malware-lu"
		description = "Yara rule to detect Crunch v4.0 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 18 00 00 00 8B C5 55 60 9C 2B 85 E9 06 00 00 89 85 E1 06 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 }

	condition:
		$a0 at pe.entry_point
}
