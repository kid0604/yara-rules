import "pe"

rule PseudoSigner01VideoLanClientAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner01 in VideoLan Client Anorganix"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }

	condition:
		$a0 at pe.entry_point
}
