import "pe"

rule PseudoSigner02BJFNT11bAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a PseudoSigner02BJFNT11bAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90 }

	condition:
		$a0 at pe.entry_point
}
