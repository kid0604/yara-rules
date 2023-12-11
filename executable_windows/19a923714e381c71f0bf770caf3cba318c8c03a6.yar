import "pe"

rule RLPackFullEdition117DLLLZMAAp0x
{
	meta:
		author = "malware-lu"
		description = "Detects RLPack Full Edition 1.17 DLL LZMA compression"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 [4] 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 [4] 6A 40 68 [4] 68 [4] 6A 00 FF 95 EB 09 00 00 89 85 }

	condition:
		$a0 at pe.entry_point
}
