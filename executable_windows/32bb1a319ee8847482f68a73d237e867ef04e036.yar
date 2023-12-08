import "pe"

rule RLPackFullEdition117aPLibAp0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPack Full Edition 1.17a PLib Ap0x"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 [15] 8D B5 74 1F 00 00 8D 9D 1E 03 00 00 33 FF [15] EB 0F FF 74 37 04 FF 34 }

	condition:
		$a0 at pe.entry_point
}
