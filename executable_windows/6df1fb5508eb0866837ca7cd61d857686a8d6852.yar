import "pe"

rule FSGv120EngdulekxtMicrosoftVisualC6070
{
	meta:
		author = "malware-lu"
		description = "Detects the FSGv120EngdulekxtMicrosoftVisualC6070 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 CD 20 EB 01 91 8D 35 80 [2] 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA }

	condition:
		$a0 at pe.entry_point
}
