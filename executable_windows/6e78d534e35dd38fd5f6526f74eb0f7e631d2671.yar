import "pe"

rule RLPack120BasicEditionaPLibAp0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPack 1.20 Basic Edition with aPLib compression"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00 EB 1B 8B 85 92 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 9E 05 00 00 00 74 0E 83 BD A2 05 00 00 00 74 05 E8 D6 01 00 00 }

	condition:
		$a0 at pe.entry_point
}
