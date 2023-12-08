import "pe"

rule PseudoSigner01CDCopsIIAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner01CDCopsIIAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 E9 }

	condition:
		$a0 at pe.entry_point
}
