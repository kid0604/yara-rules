import "pe"

rule PseudoSigner02PESHiELD025Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02PESHiELD025Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC }

	condition:
		$a0 at pe.entry_point
}
