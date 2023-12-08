import "pe"

rule PseudoSigner01PECompact14Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner01 PECompact 1.4 by Anorganix"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 EB 06 68 90 90 90 90 C3 9C 60 E8 02 90 90 90 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

	condition:
		$a0 at pe.entry_point
}
