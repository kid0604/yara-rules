import "pe"

rule FSGv120EngdulekxtMicrosoftVisualC60_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of Microsoft Visual C++ 6.0 alternate 1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 }

	condition:
		$a0 at pe.entry_point
}
