import "pe"

rule RLPack118LZMA430ap0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPack 1.18 LZMA 4.30 compression in executable files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A ?? 68 [4] 68 [4] 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 ?? 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 [4] 68 [4] 6A 00 FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }

	condition:
		$a0 at pe.entry_point
}
