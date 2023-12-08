import "pe"

rule SecureEXE30ZipWorx
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern in the entry point of a ZIPWorx executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 B8 00 00 00 [3] 00 [3] 00 [3] 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
