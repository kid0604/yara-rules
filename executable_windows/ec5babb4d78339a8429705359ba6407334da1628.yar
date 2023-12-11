import "pe"

rule DualseXe10
{
	meta:
		author = "malware-lu"
		description = "Detects DualseXe10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 08 03 00 00 89 28 33 FF 8D 85 7D 02 00 00 8D 8D 08 03 00 00 2B C8 8B 9D 58 03 00 00 E8 1C 02 00 00 8D 9D 61 02 00 00 8D B5 7C 02 00 00 46 80 3E 00 74 24 56 FF 95 0A 04 00 00 46 80 3E 00 }

	condition:
		$a0 at pe.entry_point
}
