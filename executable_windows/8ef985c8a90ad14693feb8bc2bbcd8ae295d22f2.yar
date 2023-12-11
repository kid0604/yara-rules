import "pe"

rule EXECrypt10ReBirth
{
	meta:
		author = "malware-lu"
		description = "Detects the EXECrypt10ReBirth malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 60 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 4E 28 40 00 8B F7 AC }

	condition:
		$a0 at pe.entry_point
}
