import "pe"

rule PseudoSigner01MicrosoftVisualC70DLLAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pseudo signer in Microsoft Visual C++ 7.0 DLL files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 [4] E9 }

	condition:
		$a0 at pe.entry_point
}
