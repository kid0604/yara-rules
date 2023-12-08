import "pe"

rule ExeGuarderv18Exeiconcom
{
	meta:
		author = "malware-lu"
		description = "Detects the ExeGuarderv18Exeiconcom malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 }

	condition:
		$a0 at pe.entry_point
}
