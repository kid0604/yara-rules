import "pe"

rule Thinstall25_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects Thinstall version 25 alternate 1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC B8 [4] BB [4] 50 E8 00 00 00 00 58 2D A7 1A 00 00 B9 6C 1A 00 00 BA 20 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD EC 1A 00 00 03 E8 81 75 00 [4] 81 75 04 [4] 81 75 08 [4] 81 75 0C [4] 81 75 10 }

	condition:
		$a0 at pe.entry_point
}
