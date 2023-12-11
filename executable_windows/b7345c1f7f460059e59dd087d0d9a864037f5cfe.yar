import "pe"

rule FSGv120EngdulekxtBorlandDelphiMicrosoftVisualC
{
	meta:
		author = "malware-lu"
		description = "Detects Borland Delphi or Microsoft Visual C compiled files with FSG v1.20 encryption"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 [2] 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }

	condition:
		$a0 at pe.entry_point
}
