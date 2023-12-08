import "pe"

rule PECrypter
{
	meta:
		author = "malware-lu"
		description = "Detects a specific encryption pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D EB 26 }

	condition:
		$a0 at pe.entry_point
}
