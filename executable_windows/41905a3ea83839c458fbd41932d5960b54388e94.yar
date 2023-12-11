import "pe"

rule PseudoSigner01Neolite20Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a PseudoSigner variant used by Neolite 2.0 and Anorganix"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}
