import "pe"

rule PseudoSigner01MicrosoftVisualBasic5060Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner01 Microsoft Visual Basic 5060 Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 [4] E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }

	condition:
		$a0 at pe.entry_point
}
