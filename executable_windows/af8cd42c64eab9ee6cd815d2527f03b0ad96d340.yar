import "pe"

rule Thinstall25xxJtit
{
	meta:
		author = "malware-lu"
		description = "Detects Thinstall 25xxJtit malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC B8 [4] BB [4] 50 E8 00 00 00 00 58 2D ?? 1A 00 00 B9 ?? 1A 00 00 BA ?? 1B 00 00 BE 00 10 00 00 BF ?? 53 00 00 BD ?? 1A 00 00 03 E8 81 75 00 [5] 75 04 [4] 81 75 08 [4] 81 75 0C [4] 81 75 10 }
		$a1 = { 55 8B EC B8 [4] BB [4] 50 E8 00 00 00 00 58 2D ?? 1A 00 00 B9 ?? 1A 00 00 BA ?? 1B 00 00 BE 00 10 00 00 BF ?? 53 00 00 BD ?? 1A 00 00 03 E8 81 75 00 [5] 75 04 [4] 81 75 08 [4] 81 75 0C [4] 81 75 10 [4] 03 [23] 3B F1 7C 04 3B F2 7C 02 89 2E 83 C6 04 3B F7 7C E3 58 50 68 00 00 40 00 68 80 5A }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
