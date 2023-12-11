import "pe"

rule PseudoSigner0132Lite003Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner0132Lite003Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 [4] E9 }

	condition:
		$a0 at pe.entry_point
}
