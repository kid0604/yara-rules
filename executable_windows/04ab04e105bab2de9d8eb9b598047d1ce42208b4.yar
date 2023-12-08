import "pe"

rule PseudoSigner02DEF10Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, which may indicate a PseudoSigner malware variant"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 }

	condition:
		$a0 at pe.entry_point
}
