import "pe"

rule PseudoSigner01PEtite2xlevel0Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, which may indicate a PseudoSigner malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 B8 00 90 90 00 6A 00 68 90 90 90 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68 }

	condition:
		$a0 at pe.entry_point
}
