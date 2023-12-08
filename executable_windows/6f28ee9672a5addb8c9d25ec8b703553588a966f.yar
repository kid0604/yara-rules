import "pe"

rule PseudoSigner01Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a PseudoSigner Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}
