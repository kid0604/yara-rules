import "pe"

rule SecurePE1Xwwwdeepzoneorg
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file from www.deepzone.org"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B 04 24 E8 00 00 00 00 5D 81 ED 4C 2F 40 00 89 85 61 2F 40 00 8D 9D 65 2F 40 00 53 C3 00 00 00 00 8D B5 BA 2F 40 00 8B FE BB 65 2F 40 00 B9 C6 01 00 00 AD 2B C3 C1 C0 03 33 C3 AB 43 81 FB 8E 2F 40 00 75 05 BB 65 2F 40 00 E2 E7 89 AD 1A 31 40 00 89 AD 55 34 40 00 89 AD 68 34 40 00 8D 85 BA 2F 40 00 50 C3 }

	condition:
		$a0 at pe.entry_point
}
