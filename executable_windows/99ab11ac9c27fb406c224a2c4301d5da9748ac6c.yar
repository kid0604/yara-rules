import "pe"

rule PseudoSigner01PackMaster10PEXCloneAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner01PackMaster10PEXCloneAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}
