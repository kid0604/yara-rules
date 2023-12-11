import "pe"

rule PseudoSigner02Gleam100Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, potentially indicating a PseudoSigner malware variant"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF }

	condition:
		$a0 at pe.entry_point
}
