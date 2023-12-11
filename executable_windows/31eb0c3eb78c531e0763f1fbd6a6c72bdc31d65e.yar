import "pe"

rule PseudoSigner02DxPack10Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, potentially indicating a PseudoSigner02DxPack10Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
