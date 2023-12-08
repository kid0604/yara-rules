import "pe"

rule GoatsMutilatorV16Goat_e0f
{
	meta:
		author = "malware-lu"
		description = "Detects the GoatsMutilatorV16Goat_e0f malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 EA 0B 00 00 [3] 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D }

	condition:
		$a0 at pe.entry_point
}
