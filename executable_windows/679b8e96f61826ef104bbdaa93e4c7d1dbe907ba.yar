import "pe"

rule FSGv110EngdulekxtMicrosoftVisualC60
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the FSG v1.10 Engdulekxt Microsoft Visual C 6.0 packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 }
		$a1 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE }
		$a2 = { 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 [2] 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00 }
		$a3 = { C1 CE 10 C1 F6 0F 68 00 [2] 00 2B FA 5B 23 F9 8D 15 80 [2] 00 E8 01 00 00 00 B6 5E 0B }
		$a4 = { D1 E9 03 C0 68 80 [2] 00 EB 02 CD 20 5E 40 BB F4 00 00 00 33 CA 2B C7 0F B6 16 EB 01 3E }
		$a5 = { E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE 80 [2] 00 EB 02 61 E9 68 F4 00 00 00 C1 C8 }
		$a6 = { EB 01 4D 83 F6 4C 68 80 [2] 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38 }
		$a7 = { EB 02 AB 35 EB 02 B5 C6 8D 05 80 [2] 00 C1 C2 11 BE F4 00 00 00 F7 DB F7 DB 0F BE 38 E8 }
		$a8 = { EB 02 CD 20 ?? CF [2] 80 [2] 00 [8] 00 }
		$a9 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF [2] BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point or $a4 at pe.entry_point or $a5 at pe.entry_point or $a6 at pe.entry_point or $a7 at pe.entry_point or $a8 at pe.entry_point or $a9 at pe.entry_point
}
