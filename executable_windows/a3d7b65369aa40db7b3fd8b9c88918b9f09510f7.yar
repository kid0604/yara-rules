import "pe"

rule PseudoSigner01ASPack2xxHeuristicAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a suspicious pattern in the entry point of a PE file, potentially indicating the use of the ASpack packer and the PseudoSigner tool"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }

	condition:
		$a0 at pe.entry_point
}
