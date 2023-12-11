import "pe"

rule PseudoSigner02YodasProtector102Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02YodasProtector102Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 90 90 }

	condition:
		$a0 at pe.entry_point
}
