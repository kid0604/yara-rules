import "pe"

rule PseudoSigner02MinGWGCC2xAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, potentially indicating the presence of PseudoSigner02MinGWGCC2xAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 }

	condition:
		$a0 at pe.entry_point
}
