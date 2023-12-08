import "pe"

rule PseudoSigner02ZCode101Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02ZCode101Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
