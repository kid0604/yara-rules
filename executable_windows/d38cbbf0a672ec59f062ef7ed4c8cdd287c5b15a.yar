import "pe"

rule yodasProtectorv101AshkbizDanehkar
{
	meta:
		author = "malware-lu"
		description = "Yoda's Protector v1.01 by Ashkbiz Danehkar"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
