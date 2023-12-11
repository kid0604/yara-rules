import "pe"

rule Shrinkerv34
{
	meta:
		author = "malware-lu"
		description = "Detects Shrinker v3.4 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 3D B4 [4] 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? 0B 00 00 83 C4 04 8B 75 08 A3 B4 [3] 85 F6 74 23 83 7D 0C 03 77 1D 68 FF }
		$a1 = { BB [2] BA [2] 81 C3 07 00 B8 40 B4 B1 04 D3 E8 03 C3 8C D9 49 8E C1 26 03 0E 03 00 2B }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
