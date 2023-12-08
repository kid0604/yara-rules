import "pe"

rule MEW510Northfox
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 }

	condition:
		$a0 at pe.entry_point
}
