import "pe"

rule nPackV111502006BetaNEOxuinC
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of nPackV111502006BetaNEOxuinC malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 3D 40 [3] 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 [3] 2B 05 08 [3] A3 3C [3] E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 3C [3] C7 05 40 [3] 01 00 00 00 01 05 00 [3] FF 35 00 [3] C3 C3 }

	condition:
		$a0 at pe.entry_point
}
