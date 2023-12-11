import "pe"

rule PseudoSigner01MicrosoftVisualBasic60DLLAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a PseudoSigner in Microsoft Visual Basic 6.0 DLL files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 5A 68 90 90 90 90 68 90 90 90 90 52 E9 90 90 FF }

	condition:
		$a0 at pe.entry_point
}
