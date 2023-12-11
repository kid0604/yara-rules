import "pe"

rule PseudoSigner02UPX06Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02UPX06Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
