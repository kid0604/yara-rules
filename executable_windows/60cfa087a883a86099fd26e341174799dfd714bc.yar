import "pe"

rule yodasProtector10xAshkbizDanehkar
{
	meta:
		author = "malware-lu"
		description = "Detects Yoda's Protector 10x Ashkbiz Danehkar malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 }

	condition:
		$a0 at pe.entry_point
}
