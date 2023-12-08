import "pe"

rule PseudoSigner01PEX099Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner01PEX099Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 E9 }

	condition:
		$a0 at pe.entry_point
}
