import "pe"

rule PCGuardforWin32v500SofProBlagojeCeklic
{
	meta:
		author = "malware-lu"
		description = "Detects PCGuard for Win32 v5.00 SofPro by Blagoje Ceklic"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 [3] 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C }

	condition:
		$a0 at pe.entry_point
}
