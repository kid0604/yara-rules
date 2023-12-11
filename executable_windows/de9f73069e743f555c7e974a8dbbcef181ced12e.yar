import "pe"

rule NsPack30NorthStar
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of NsPack 3.0 North Star packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 [2] FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 [2] FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 [2] FF FF 89 95 [2] FF FF 01 95 [2] FF FF 8D B5 [2] FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 [2] FF FF 85 C0 0F 84 6A 03 00 00 89 85 [2] FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD [2] FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }

	condition:
		$a0 at pe.entry_point
}
