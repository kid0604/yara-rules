import "pe"

rule XXPack01bagie
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of XXPack01bagie malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 00 68 00 [3] C3 }

	condition:
		$a0 at pe.entry_point
}
