import "pe"

rule AntiDote12DemoSISTeam
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting AntiDote12DemoSISTeam malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 F7 FE FF FF 05 CB 22 00 00 FF E0 E8 EB FE FF FF 05 BB 19 00 00 FF E0 E8 BD 00 00 00 08 B2 62 00 01 52 17 0C 0F 2C 2B 20 7F 52 79 01 30 07 17 29 4F 01 3C 30 2B 5A 3D C7 26 11 26 06 59 0E 78 2E 10 14 0B 13 1A 1A 3F 64 1D 71 33 57 21 09 24 8B 1B 09 37 08 61 0F 1D 1D 2A 01 87 35 4C 07 39 0B }

	condition:
		$a0
}
