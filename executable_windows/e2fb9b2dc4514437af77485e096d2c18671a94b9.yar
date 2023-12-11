import "pe"

rule RLPackFullEdition117iBoxaPLibAp0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPack Full Edition 1.17 iBoxaPLibAp0x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 [15] 8D B5 79 29 00 00 8D 9D 2C 03 00 00 33 FF [15] EB 0F FF 74 37 04 FF 34 }

	condition:
		$a0 at pe.entry_point
}
