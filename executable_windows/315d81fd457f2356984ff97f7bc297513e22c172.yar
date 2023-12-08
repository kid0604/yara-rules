import "pe"

rule PseudoSigner02MacromediaFlashProjector60Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02 Macromedia Flash Projector 6.0 Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

	condition:
		$a0 at pe.entry_point
}
