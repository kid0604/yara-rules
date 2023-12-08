import "pe"

rule PseudoSigner02WatcomCCDLLAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02 Watcom C/C++ DLL Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1 }

	condition:
		$a0 at pe.entry_point
}
