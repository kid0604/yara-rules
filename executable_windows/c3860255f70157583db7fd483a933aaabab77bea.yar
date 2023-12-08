import "pe"

rule PseudoSigner01MEW11SE10Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, which may indicate a pseudo signer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9 }

	condition:
		$a0 at pe.entry_point
}
