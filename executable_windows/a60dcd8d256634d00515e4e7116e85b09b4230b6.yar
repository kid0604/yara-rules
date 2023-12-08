import "pe"

rule BobPackv100BoBBobSoft
{
	meta:
		author = "malware-lu"
		description = "Detects BobPackv100BoBBobSoft malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED [4] E8 3D 00 00 00 89 85 [4] 89 C2 B8 5D 0A 00 00 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01 }

	condition:
		$a0 at pe.entry_point
}
