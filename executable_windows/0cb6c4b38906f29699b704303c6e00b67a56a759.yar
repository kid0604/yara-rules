import "pe"

rule PseudoSigner02CodeSafe20Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02CodeSafe20Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 }

	condition:
		$a0 at pe.entry_point
}
