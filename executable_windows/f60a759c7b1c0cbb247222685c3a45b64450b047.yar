import "pe"

rule PseudoSigner01FSG131Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, potentially indicating a pseudo signer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9 }

	condition:
		$a0 at pe.entry_point
}
