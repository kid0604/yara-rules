import "pe"

rule PseudoSigner02FSG131Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02FSG131Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }

	condition:
		$a0 at pe.entry_point
}
