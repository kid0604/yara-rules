import "pe"

rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualC_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects Borland Delphi or Microsoft Visual C compiled malware using alternate FSGv110Engdulekxt packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 [2] 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
		$a1 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 [2] 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
