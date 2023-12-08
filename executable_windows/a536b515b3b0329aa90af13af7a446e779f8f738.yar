import "pe"

rule PseudoSigner02NorthStarPEShrinker13Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02NorthStarPEShrinker13Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
