import "pe"

rule FSGv110EngdulekxtBorlandDelphiBorlandC
{
	meta:
		author = "malware-lu"
		description = "Detects Borland Delphi or Borland C compiler used in malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E [2] 18 EB 02 AB A0 03 F7 }
		$a1 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E [2] 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
		$a2 = { EB 01 2E EB 02 A5 55 BB 80 [2] 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}
