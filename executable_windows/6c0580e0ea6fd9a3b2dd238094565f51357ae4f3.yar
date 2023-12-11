import "pe"

rule PseudoSigner02LCCWin321xAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02LCCWin321xAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 [4] 68 9A 10 40 90 50 }

	condition:
		$a0 at pe.entry_point
}
