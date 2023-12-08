import "pe"

rule PseudoSigner02REALBasicAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, potentially indicating a PseudoSigner02REALBasicAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 }

	condition:
		$a0 at pe.entry_point
}
