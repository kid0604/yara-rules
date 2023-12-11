import "pe"

rule eXcaliburv103forgotus
{
	meta:
		author = "malware-lu"
		description = "Detects the eXcaliburv103forgotus malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 20 45 78 63 61 6C 69 62 75 72 20 28 63 29 20 62 79 20 66 6F 72 67 6F 74 2F 75 53 2F 44 46 43 47 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }

	condition:
		$a0 at pe.entry_point
}
