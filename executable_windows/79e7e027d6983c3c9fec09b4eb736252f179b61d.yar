import "pe"

rule PseudoSigner02BorlandCDLLMethod2Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02BorlandCDLLMethod2Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}
