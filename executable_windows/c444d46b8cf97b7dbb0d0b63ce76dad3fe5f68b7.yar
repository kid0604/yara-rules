import "pe"

rule FSGv110EngdulekxtMicrosoftVisualC6070
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of FSG v1.10 Engdulekxt Microsoft Visual C6.0 packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 [2] 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27 }
		$a1 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 [3] EB 02 CD 20 03 D3 8D 35 F4 00 }
		$a2 = { 87 FE E8 02 00 00 00 98 CC 5F BB 80 [2] 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3 }
		$a3 = { F7 D8 40 49 EB 02 E0 0A 8D 35 80 [3] 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80 }
		$a4 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point or $a4 at pe.entry_point
}
