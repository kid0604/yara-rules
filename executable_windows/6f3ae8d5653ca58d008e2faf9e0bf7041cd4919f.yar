import "pe"

rule diProtectorV1XdiProtectorSoftware
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting diProtectorV1X diProtectorSoftware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 01 00 A0 E3 14 00 00 EB 00 00 20 E0 44 10 9F E5 03 2A A0 E3 40 30 A0 E3 AE 00 00 EB 30 00 8F E5 00 20 A0 E1 3A 0E 8F E2 00 00 80 E2 1C 10 9F E5 20 30 8F E2 0E 00 00 EB 14 00 9F E5 14 10 9F E5 7F 20 A0 E3 C5 00 00 EB 04 C0 8F E2 00 F0 9C E5 }

	condition:
		$a0 at pe.entry_point
}
