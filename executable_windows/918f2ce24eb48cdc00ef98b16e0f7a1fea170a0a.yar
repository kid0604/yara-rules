import "pe"

rule PseudoSigner01ACProtect109Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a PseudoSigner 01ACProtect 109 Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}
