import "pe"

rule PseudoSigner01CodeLockAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner01CodeLockAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B E9 }

	condition:
		$a0 at pe.entry_point
}
