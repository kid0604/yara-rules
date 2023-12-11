import "pe"

rule SpecialEXEPasswordProtectorv10
{
	meta:
		author = "malware-lu"
		description = "Detects SpecialEXEPasswordProtectorv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 }

	condition:
		$a0 at pe.entry_point
}
