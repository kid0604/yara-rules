import "pe"

rule PseudoSigner02ExeSmasherAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of an executable file, which may indicate a PseudoSigner02ExeSmasherAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B }

	condition:
		$a0 at pe.entry_point
}
