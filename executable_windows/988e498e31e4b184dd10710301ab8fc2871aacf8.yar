import "pe"

rule PseudoSigner02VOBProtectCD5Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02VOBProtectCD5Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 36 3E 26 8A C0 60 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
