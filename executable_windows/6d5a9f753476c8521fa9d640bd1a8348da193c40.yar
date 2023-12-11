import "pe"

rule RLPackFullEdition117LZMAAp0x
{
	meta:
		author = "malware-lu"
		description = "Detects RLPack Full Edition 1.17 LZMA compressed executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 [15] 8D B5 73 26 00 00 8D 9D 58 03 00 00 33 FF [10] 6A 40 68 [4] 68 [4] 6A }

	condition:
		$a0 at pe.entry_point
}
