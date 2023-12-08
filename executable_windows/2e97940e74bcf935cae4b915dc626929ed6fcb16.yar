import "pe"

rule yodasProtectorv1033exescrcomAshkbizDanehkar
{
	meta:
		author = "malware-lu"
		description = "Yoda's Protector v1.033 executable script used by Ashkbiz Danehkar"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 }

	condition:
		$a0 at pe.entry_point
}
