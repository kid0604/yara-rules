import "pe"

rule RLPackFullEdition117Ap0x
{
	meta:
		author = "malware-lu"
		description = "Detects RLPack Full Edition 1.17 Ap0x"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 [15] 8D B5 [4] 8D 9D [4] 33 FF }

	condition:
		$a0 at pe.entry_point
}
