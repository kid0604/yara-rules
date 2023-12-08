import "pe"

rule nPackv11150200BetaNEOx
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of nPackv11150200BetaNEOx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 3D 40 [3] 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 [3] 2B 05 08 [3] A3 3C [2] 00 E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 }

	condition:
		$a0 at pe.entry_point
}
