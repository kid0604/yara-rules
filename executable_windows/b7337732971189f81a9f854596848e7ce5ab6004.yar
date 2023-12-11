import "pe"

rule MoleBoxv254Teggo
{
	meta:
		author = "malware-lu"
		description = "Detects MoleBoxv254Teggo malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 8B 4D F0 8B 11 89 15 [3] 00 8B 45 FC A3 [3] 00 5F 5E 8B E5 5D C3 CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 24 61 58 58 FF D0 E8 [2] 00 00 6A 00 FF 15 [3] 00 CC CC CC CC CC CC CC CC CC CC CC CC CC CC }

	condition:
		$a0
}
