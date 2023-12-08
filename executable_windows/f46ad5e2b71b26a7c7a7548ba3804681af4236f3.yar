import "pe"

rule nPackv11250BetaNEOx
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of nPackv11250BetaNEOx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 3D 04 [3] 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 2E [3] 2B 05 08 [3] A3 00 [3] E8 9C 00 00 00 E8 04 02 00 00 E8 FB 06 00 00 E8 1B 06 00 00 A1 00 [3] C7 05 04 [3] 01 00 00 00 01 05 00 [3] FF 35 00 }

	condition:
		$a0 at pe.entry_point
}
