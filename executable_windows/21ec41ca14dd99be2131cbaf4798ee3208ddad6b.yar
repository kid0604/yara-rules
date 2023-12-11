import "pe"

rule PseudoSigner02BorlandC1999Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02BorlandC1999Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 [4] A3 }

	condition:
		$a0 at pe.entry_point
}
