import "pe"

rule mkfpackllydd
{
	meta:
		author = "malware-lu"
		description = "Detects a specific packer used by malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 5B 81 EB 05 00 00 00 8B 93 9F 08 00 00 53 6A 40 68 00 10 00 00 52 6A 00 FF 93 32 08 00 00 5B 8B F0 8B BB 9B 08 00 00 03 FB 56 57 E8 86 08 00 00 83 C4 08 8D 93 BB 08 00 00 52 53 FF E6 }

	condition:
		$a0
}
