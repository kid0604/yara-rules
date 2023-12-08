import "pe"

rule PseudoSigner01MicrosoftVisualC50MFCAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific PseudoSigner in Microsoft Visual C++ 5.0 MFC Anorganix"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 E9 }

	condition:
		$a0 at pe.entry_point
}
