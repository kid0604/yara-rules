import "pe"

rule PseudoSigner01LocklessIntroPackAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner01LocklessIntroPackAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD E9 }

	condition:
		$a0 at pe.entry_point
}
