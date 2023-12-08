import "pe"

rule ZipWorxSecureEXEv25ZipWORXTechnologiesLLC
{
	meta:
		author = "malware-lu"
		description = "Detects ZipWorx Secure EXE v2.5 files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 B8 00 00 00 [12] 00 00 00 00 00 [10] 00 53 65 63 75 72 65 45 58 45 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 28 63 29 20 32 30 }

	condition:
		$a0 at pe.entry_point
}
