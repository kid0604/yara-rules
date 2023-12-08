import "pe"

rule PseudoSigner01MicrosoftVisualC60DebugVersionAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a PseudoSigner in Microsoft Visual C++ 6.0 Debug Version Anorganix"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 51 90 90 90 01 01 90 90 90 90 68 [4] 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}
