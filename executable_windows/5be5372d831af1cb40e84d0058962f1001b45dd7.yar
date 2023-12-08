import "pe"

rule NullsoftInstallSystemv20RC2
{
	meta:
		author = "malware-lu"
		description = "Detects Nullsoft Install System v2.0 RC2"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }

	condition:
		$a0
}
