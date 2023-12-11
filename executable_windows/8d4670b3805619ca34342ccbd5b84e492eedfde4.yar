import "pe"

rule RLPackV115V117Dllap0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPack v1.15-v1.17 DLL at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF E8 }

	condition:
		$a0 at pe.entry_point
}
