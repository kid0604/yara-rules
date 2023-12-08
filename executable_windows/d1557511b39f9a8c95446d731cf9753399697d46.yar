import "pe"

rule PeCompact253DLLSlimLoaderBitSumTechnologies
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PeCompact 2.53 DLL Slim Loader by BitSum Technologies"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D 0B 6B 65 72 6E 6C 33 32 }

	condition:
		$a0 at pe.entry_point
}
