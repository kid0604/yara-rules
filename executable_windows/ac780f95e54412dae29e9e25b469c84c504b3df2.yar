import "pe"

rule tElock099cPrivateECLIPSEtE
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of tElock099cPrivateECLIPSEtE malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 3F DF FF FF 00 00 00 [4] 04 [2] 00 00 00 00 00 00 00 00 00 24 [2] 00 14 [2] 00 0C [2] 00 00 00 00 00 00 00 00 00 31 [2] 00 1C [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3C [2] 00 00 00 00 00 4F [2] 00 00 00 00 00 3C [2] 00 00 00 00 00 4F [2] 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }

	condition:
		$a0 at pe.entry_point
}
