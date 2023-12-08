import "pe"

rule PseudoSigner01PESHiELD025Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific PseudoSigner01PESHiELD025Anorganix malware variant"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC E9 }

	condition:
		$a0 at pe.entry_point
}
