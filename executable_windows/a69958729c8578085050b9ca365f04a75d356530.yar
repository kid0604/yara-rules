import "pe"

rule PseudoSigner01YodasProtector102Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, which may indicate a pseudo signer or Yoda's Protector 1.02 Anorganix"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 90 90 E9 }

	condition:
		$a0 at pe.entry_point
}
