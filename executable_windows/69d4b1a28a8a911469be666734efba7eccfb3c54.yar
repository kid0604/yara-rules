import "pe"

rule PeCompact2253276BitSumTechnologies
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting PeCompact 2.25 32/76 Bit Sum Technologies"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 55 53 51 57 56 52 8D 98 C9 11 00 10 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 5A 8B F8 50 52 8B 33 8B 43 20 03 C2 8B 08 89 4B 20 8B 43 1C 03 C2 8B 08 89 4B 1C 03 F2 8B 4B 0C 03 CA 8D 43 1C 50 57 56 FF }

	condition:
		$a0
}
