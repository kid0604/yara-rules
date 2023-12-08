import "pe"

rule MoleBoxv230Teggo
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of MoleBox v2.3.0 Teggo packed executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 42 04 E8 [2] 00 00 A3 [3] 00 8B 4D F0 8B 11 89 15 [3] 00 ?? 45 FC A3 [3] 00 5F 5E 8B E5 5D C3 CC CC CC CC CC CC CC CC CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 20 61 58 FF D0 E8 [2] 00 00 CC CC CC CC CC CC CC }

	condition:
		$a0
}
