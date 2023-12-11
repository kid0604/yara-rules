import "pe"

rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualCx
{
	meta:
		author = "malware-lu"
		description = "Detects Borland Delphi or Microsoft Visual C++ packed with FSG v1.10 Engdulekxt"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 [2] 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }

	condition:
		$a0 at pe.entry_point
}
