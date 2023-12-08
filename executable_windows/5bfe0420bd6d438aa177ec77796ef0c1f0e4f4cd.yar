import "pe"

rule EXEStealthv274_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the EXEStealth v2.74 alternate 1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 00 EB 17 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 60 90 E8 00 00 00 00 5D 81 ED C4 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 }

	condition:
		$a0
}
