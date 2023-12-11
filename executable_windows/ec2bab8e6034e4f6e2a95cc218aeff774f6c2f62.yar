import "pe"

rule PseudoSigner02ASProtectAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02ASProtectAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }

	condition:
		$a0 at pe.entry_point
}
