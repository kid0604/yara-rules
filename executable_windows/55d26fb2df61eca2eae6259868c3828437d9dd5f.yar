import "pe"

rule PEncrypt20junkcode
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of junk code used by the PEncrypt 2.0 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 25 00 00 F7 BF 00 00 00 00 00 00 00 00 00 00 12 00 E8 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 00 00 E8 00 00 00 00 5D 81 ED 2C 10 40 00 8D B5 14 10 40 00 E8 33 00 00 00 89 85 10 10 40 00 BF 00 00 40 00 8B F7 03 7F 3C 8B 4F 54 51 56 8D 85 }

	condition:
		$a0 at pe.entry_point
}
