import "pe"

rule PseudoSigner01FSG10Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, potentially indicating a PseudoSigner malware variant"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B E9 }

	condition:
		$a0 at pe.entry_point
}
