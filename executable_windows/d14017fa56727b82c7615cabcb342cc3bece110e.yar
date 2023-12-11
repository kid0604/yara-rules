import "pe"

rule CRYPToCRACksPEProtectorV092LukasFleischer
{
	meta:
		author = "malware-lu"
		description = "Detects CRYPToCRACksPEProtectorV092LukasFleischer malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 [2] 81 3E 50 45 00 00 75 26 }

	condition:
		$a0 at pe.entry_point
}
