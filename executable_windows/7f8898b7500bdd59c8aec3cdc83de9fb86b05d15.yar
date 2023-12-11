import "pe"

rule DalKrypt10byDalKiT
{
	meta:
		author = "malware-lu"
		description = "Detects the DalKrypt10 malware by DalKiT"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 00 10 40 00 58 68 [3] 00 5F 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB [3] 00 72 EB FF E7 }

	condition:
		$a0 at pe.entry_point
}
