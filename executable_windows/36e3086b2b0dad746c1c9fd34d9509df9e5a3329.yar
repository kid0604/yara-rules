import "pe"

rule XtremeProtectorv106
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting XtremeProtectorv106 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [3] 00 B9 75 [2] 00 50 51 E8 05 00 00 00 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF 00 00 00 02 }

	condition:
		$a0 at pe.entry_point
}
