import "pe"

rule PseudoSigner01WATCOMCCEXEAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a Windows Watcom C/C++ executable file, which may indicate a pseudo signer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 00 00 00 00 90 90 90 90 57 41 E9 }

	condition:
		$a0 at pe.entry_point
}
