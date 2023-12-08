import "pe"

rule PseudoSigner02MicrosoftVisualBasic5060Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, potentially indicating a PseudoSigner02MicrosoftVisualBasic5060Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 [4] E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
