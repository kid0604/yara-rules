import "pe"

rule RLPackV115V117aPlib043ap0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPack v1.15 - v1.17a with PLib 0.43a"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

	condition:
		$a0 at pe.entry_point
}
