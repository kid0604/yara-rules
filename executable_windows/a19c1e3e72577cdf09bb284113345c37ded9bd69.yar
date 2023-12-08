import "pe"

rule RLPackFullEdition117DLLAp0x
{
	meta:
		author = "malware-lu"
		description = "Detects RLPack Full Edition 1.17 DLL Ap0x"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 [4] 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF E8 }

	condition:
		$a0 at pe.entry_point
}
