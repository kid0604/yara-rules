import "pe"

rule PseudoSigner02LCCWin32DLLAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02LCCWin32DLLAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }

	condition:
		$a0 at pe.entry_point
}
