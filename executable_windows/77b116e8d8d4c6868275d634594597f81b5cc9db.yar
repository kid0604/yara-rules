import "pe"

rule RLPackV115V117LZMA430ap0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPack version 1.15 or 1.17 using LZMA 4.30 compression"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF E8 83 01 00 00 6A ?? 68 [4] 68 [4] 6A ?? FF 95 [4] 89 85 [4] EB 14 }

	condition:
		$a0 at pe.entry_point
}
