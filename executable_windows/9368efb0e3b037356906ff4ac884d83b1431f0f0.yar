import "pe"

rule diPackerV1XdiProtectorSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of diPackerV1X or diProtector software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0F 00 2D E9 01 00 A0 E3 68 01 00 EB 8C 00 00 EB 2B 00 00 EB 00 00 20 E0 1C 10 8F E2 8E 20 8F E2 00 30 A0 E3 67 01 00 EB 0F 00 BD E8 00 C0 8F E2 00 F0 9C E5 }

	condition:
		$a0 at pe.entry_point
}
