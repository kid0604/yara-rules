import "pe"

rule PocketPCARM
{
	meta:
		author = "malware-lu"
		description = "Detects PocketPC ARM executable files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { F0 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 ?? 00 00 EB 07 30 A0 E1 06 20 A0 E1 05 10 A0 E1 04 00 A0 E1 [3] EB F0 40 BD E8 ?? 00 00 EA ?? 40 2D E9 [2] 9F E5 [5] 00 [8] 9F E5 00 [4] 00 }

	condition:
		$a0 at pe.entry_point
}
