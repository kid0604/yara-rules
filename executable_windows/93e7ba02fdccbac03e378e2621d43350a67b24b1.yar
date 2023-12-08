import "pe"

rule PseudoSigner02WATCOMCCEXEAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a Windows executable file, possibly indicating a pseudo signer using Watcom C/C++ compiler"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 00 00 00 00 90 90 90 90 57 41 }

	condition:
		$a0 at pe.entry_point
}
