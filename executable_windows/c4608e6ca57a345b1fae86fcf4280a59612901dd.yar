import "pe"

rule PseudoSigner02Armadillo300Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02Armadillo300Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 }

	condition:
		$a0 at pe.entry_point
}
