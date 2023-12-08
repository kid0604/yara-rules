import "pe"

rule RLPackFullEdition117DLLaPLibAp0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPack Full Edition 1.17 DLLaPLibAp0x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 [4] 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 53 03 00 00 8D 9D 02 02 00 00 33 FF E8 [4] EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 }

	condition:
		$a0 at pe.entry_point
}
