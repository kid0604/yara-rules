import "pe"

rule PseudoSigner01ASProtectAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a file signed with PseudoSigner01ASProtectAnorganix"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9 }

	condition:
		$a0 at pe.entry_point
}
