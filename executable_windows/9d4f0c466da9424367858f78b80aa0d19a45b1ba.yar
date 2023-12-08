import "pe"

rule NullsoftInstallSystemv20b2v20b3
{
	meta:
		author = "malware-lu"
		description = "Detects Nullsoft Install System v2.0b2 and v2.0b3"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 [3] 00 57 FF 15 [2] 40 00 57 FF 15 }

	condition:
		$a0 at pe.entry_point
}
